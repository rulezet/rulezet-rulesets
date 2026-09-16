rule TTP_XOR_MULT_DOSStub_55a0 {
  strings:
    $key_55a0 = { 01 c8 [2] 75 d0 [2] 32 d2 [2] 75 c3 [2] 3b cf [2] 37 c5 [2] 20 ce [2] 3b 80 [2] 06 }

  condition:
    any of them
}