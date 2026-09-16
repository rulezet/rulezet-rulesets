rule TTP_XOR_MULT_DOSStub_21a0 {
  strings:
    $key_21a0 = { 75 c8 [2] 01 d0 [2] 46 d2 [2] 01 c3 [2] 4f cf [2] 43 c5 [2] 54 ce [2] 4f 80 [2] 72 }

  condition:
    any of them
}