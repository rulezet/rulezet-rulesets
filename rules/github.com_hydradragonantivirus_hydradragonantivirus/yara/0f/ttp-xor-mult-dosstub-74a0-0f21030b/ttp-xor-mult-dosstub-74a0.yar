rule TTP_XOR_MULT_DOSStub_74a0 {
  strings:
    $key_74a0 = { 20 c8 [2] 54 d0 [2] 13 d2 [2] 54 c3 [2] 1a cf [2] 16 c5 [2] 01 ce [2] 1a 80 [2] 27 }

  condition:
    any of them
}