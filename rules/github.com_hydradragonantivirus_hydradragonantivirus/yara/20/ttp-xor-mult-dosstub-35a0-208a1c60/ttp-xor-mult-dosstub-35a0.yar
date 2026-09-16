rule TTP_XOR_MULT_DOSStub_35a0 {
  strings:
    $key_35a0 = { 61 c8 [2] 15 d0 [2] 52 d2 [2] 15 c3 [2] 5b cf [2] 57 c5 [2] 40 ce [2] 5b 80 [2] 66 }

  condition:
    any of them
}