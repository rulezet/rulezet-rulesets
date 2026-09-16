rule TTP_XOR_MULT_DOSStub_16a0 {
  strings:
    $key_16a0 = { 42 c8 [2] 36 d0 [2] 71 d2 [2] 36 c3 [2] 78 cf [2] 74 c5 [2] 63 ce [2] 78 80 [2] 45 }

  condition:
    any of them
}