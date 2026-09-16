rule TTP_XOR_MULT_DOSStub_26a0 {
  strings:
    $key_26a0 = { 72 c8 [2] 06 d0 [2] 41 d2 [2] 06 c3 [2] 48 cf [2] 44 c5 [2] 53 ce [2] 48 80 [2] 75 }

  condition:
    any of them
}