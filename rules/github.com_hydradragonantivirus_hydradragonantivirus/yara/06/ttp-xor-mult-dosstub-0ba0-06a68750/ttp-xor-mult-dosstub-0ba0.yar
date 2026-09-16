rule TTP_XOR_MULT_DOSStub_0ba0 {
  strings:
    $key_0ba0 = { 5f c8 [2] 2b d0 [2] 6c d2 [2] 2b c3 [2] 65 cf [2] 69 c5 [2] 7e ce [2] 65 80 [2] 58 }

  condition:
    any of them
}