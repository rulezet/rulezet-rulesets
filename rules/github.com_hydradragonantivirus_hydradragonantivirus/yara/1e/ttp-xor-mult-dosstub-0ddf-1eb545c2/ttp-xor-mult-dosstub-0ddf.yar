rule TTP_XOR_MULT_DOSStub_0ddf {
  strings:
    $key_0ddf = { 59 b7 [2] 2d af [2] 6a ad [2] 2d bc [2] 63 b0 [2] 6f ba [2] 78 b1 [2] 63 ff [2] 5e }

  condition:
    any of them
}