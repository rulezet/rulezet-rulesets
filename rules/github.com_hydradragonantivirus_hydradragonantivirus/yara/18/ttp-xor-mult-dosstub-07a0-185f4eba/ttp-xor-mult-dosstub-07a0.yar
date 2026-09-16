rule TTP_XOR_MULT_DOSStub_07a0 {
  strings:
    $key_07a0 = { 53 c8 [2] 27 d0 [2] 60 d2 [2] 27 c3 [2] 69 cf [2] 65 c5 [2] 72 ce [2] 69 80 [2] 54 }

  condition:
    any of them
}