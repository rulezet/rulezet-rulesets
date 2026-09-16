rule TTP_XOR_MULT_DOSStub_1ba0 {
  strings:
    $key_1ba0 = { 4f c8 [2] 3b d0 [2] 7c d2 [2] 3b c3 [2] 75 cf [2] 79 c5 [2] 6e ce [2] 75 80 [2] 48 }

  condition:
    any of them
}