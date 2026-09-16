rule TTP_XOR_MULT_DOSStub_75a0 {
  strings:
    $key_75a0 = { 21 c8 [2] 55 d0 [2] 12 d2 [2] 55 c3 [2] 1b cf [2] 17 c5 [2] 00 ce [2] 1b 80 [2] 26 }

  condition:
    any of them
}