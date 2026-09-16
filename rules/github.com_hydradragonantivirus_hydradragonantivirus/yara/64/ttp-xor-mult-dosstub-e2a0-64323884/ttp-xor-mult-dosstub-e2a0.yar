rule TTP_XOR_MULT_DOSStub_e2a0 {
  strings:
    $key_e2a0 = { b6 c8 [2] c2 d0 [2] 85 d2 [2] c2 c3 [2] 8c cf [2] 80 c5 [2] 97 ce [2] 8c 80 [2] b1 }

  condition:
    any of them
}