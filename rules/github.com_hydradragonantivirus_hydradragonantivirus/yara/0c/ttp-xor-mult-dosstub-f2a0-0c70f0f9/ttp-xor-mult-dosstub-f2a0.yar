rule TTP_XOR_MULT_DOSStub_f2a0 {
  strings:
    $key_f2a0 = { a6 c8 [2] d2 d0 [2] 95 d2 [2] d2 c3 [2] 9c cf [2] 90 c5 [2] 87 ce [2] 9c 80 [2] a1 }

  condition:
    any of them
}