rule TTP_XOR_MULT_DOSStub_3ba0 {
  strings:
    $key_3ba0 = { 6f c8 [2] 1b d0 [2] 5c d2 [2] 1b c3 [2] 55 cf [2] 59 c5 [2] 4e ce [2] 55 80 [2] 68 }

  condition:
    any of them
}