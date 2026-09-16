rule TTP_XOR_MULT_DOSStub_b6a0 {
  strings:
    $key_b6a0 = { e2 c8 [2] 96 d0 [2] d1 d2 [2] 96 c3 [2] d8 cf [2] d4 c5 [2] c3 ce [2] d8 80 [2] e5 }

  condition:
    any of them
}