rule TTP_XOR_MULT_DOSStub_10a0 {
  strings:
    $key_10a0 = { 44 c8 [2] 30 d0 [2] 77 d2 [2] 30 c3 [2] 7e cf [2] 72 c5 [2] 65 ce [2] 7e 80 [2] 43 }

  condition:
    any of them
}