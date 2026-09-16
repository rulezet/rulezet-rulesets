rule TTP_XOR_MULT_DOSStub_67a0 {
  strings:
    $key_67a0 = { 33 c8 [2] 47 d0 [2] 00 d2 [2] 47 c3 [2] 09 cf [2] 05 c5 [2] 12 ce [2] 09 80 [2] 34 }

  condition:
    any of them
}