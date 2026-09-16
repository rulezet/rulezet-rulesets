rule TTP_XOR_MULT_DOSStub_fddf {
  strings:
    $key_fddf = { a9 b7 [2] dd af [2] 9a ad [2] dd bc [2] 93 b0 [2] 9f ba [2] 88 b1 [2] 93 ff [2] ae }

  condition:
    any of them
}