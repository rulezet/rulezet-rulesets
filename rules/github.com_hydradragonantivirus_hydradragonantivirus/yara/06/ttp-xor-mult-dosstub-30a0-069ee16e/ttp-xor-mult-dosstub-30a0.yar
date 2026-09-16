rule TTP_XOR_MULT_DOSStub_30a0 {
  strings:
    $key_30a0 = { 64 c8 [2] 10 d0 [2] 57 d2 [2] 10 c3 [2] 5e cf [2] 52 c5 [2] 45 ce [2] 5e 80 [2] 63 }

  condition:
    any of them
}