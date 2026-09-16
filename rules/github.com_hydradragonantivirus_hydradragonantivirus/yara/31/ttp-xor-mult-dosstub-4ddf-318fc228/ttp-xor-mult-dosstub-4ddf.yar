rule TTP_XOR_MULT_DOSStub_4ddf {
  strings:
    $key_4ddf = { 19 b7 [2] 6d af [2] 2a ad [2] 6d bc [2] 23 b0 [2] 2f ba [2] 38 b1 [2] 23 ff [2] 1e }

  condition:
    any of them
}