rule TTP_XOR_MULT_DOSStub_14a0 {
  strings:
    $key_14a0 = { 40 c8 [2] 34 d0 [2] 73 d2 [2] 34 c3 [2] 7a cf [2] 76 c5 [2] 61 ce [2] 7a 80 [2] 47 }

  condition:
    any of them
}