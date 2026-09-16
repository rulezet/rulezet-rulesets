rule TTP_XOR_MULT_DOSStub_1ddf {
  strings:
    $key_1ddf = { 49 b7 [2] 3d af [2] 7a ad [2] 3d bc [2] 73 b0 [2] 7f ba [2] 68 b1 [2] 73 ff [2] 4e }

  condition:
    any of them
}