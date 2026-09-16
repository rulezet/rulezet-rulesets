rule TTP_XOR_MULT_DOSStub_5ddf {
  strings:
    $key_5ddf = { 09 b7 [2] 7d af [2] 3a ad [2] 7d bc [2] 33 b0 [2] 3f ba [2] 28 b1 [2] 33 ff [2] 0e }

  condition:
    any of them
}