rule TTP_XOR_MULT_DOSStub_b5a1 {
  strings:
    $key_b5a1 = { e1 c9 [2] 95 d1 [2] d2 d3 [2] 95 c2 [2] db ce [2] d7 c4 [2] c0 cf [2] db 81 [2] e6 }

  condition:
    any of them
}