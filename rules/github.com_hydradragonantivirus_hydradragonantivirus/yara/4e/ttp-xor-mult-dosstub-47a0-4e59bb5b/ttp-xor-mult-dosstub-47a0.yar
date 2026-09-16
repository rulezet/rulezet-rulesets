rule TTP_XOR_MULT_DOSStub_47a0 {
  strings:
    $key_47a0 = { 13 c8 [2] 67 d0 [2] 20 d2 [2] 67 c3 [2] 29 cf [2] 25 c5 [2] 32 ce [2] 29 80 [2] 14 }

  condition:
    any of them
}