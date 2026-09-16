rule TTP_XOR_MULT_DOSStub_6ddf {
  strings:
    $key_6ddf = { 39 b7 [2] 4d af [2] 0a ad [2] 4d bc [2] 03 b0 [2] 0f ba [2] 18 b1 [2] 03 ff [2] 3e }

  condition:
    any of them
}