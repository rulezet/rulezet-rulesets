rule TTP_XOR_MULT_DOSStub_37a0 {
  strings:
    $key_37a0 = { 63 c8 [2] 17 d0 [2] 50 d2 [2] 17 c3 [2] 59 cf [2] 55 c5 [2] 42 ce [2] 59 80 [2] 64 }

  condition:
    any of them
}