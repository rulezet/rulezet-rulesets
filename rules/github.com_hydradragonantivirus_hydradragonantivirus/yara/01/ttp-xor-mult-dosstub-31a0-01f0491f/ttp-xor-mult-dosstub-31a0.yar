rule TTP_XOR_MULT_DOSStub_31a0 {
  strings:
    $key_31a0 = { 65 c8 [2] 11 d0 [2] 56 d2 [2] 11 c3 [2] 5f cf [2] 53 c5 [2] 44 ce [2] 5f 80 [2] 62 }

  condition:
    any of them
}