rule TTP_XOR_MULT_DOSStub_ead7 {
  strings:
    $key_ead7 = { be bf [2] ca a7 [2] 8d a5 [2] ca b4 [2] 84 b8 [2] 88 b2 [2] 9f b9 [2] 84 f7 [2] b9 }

  condition:
    any of them
}