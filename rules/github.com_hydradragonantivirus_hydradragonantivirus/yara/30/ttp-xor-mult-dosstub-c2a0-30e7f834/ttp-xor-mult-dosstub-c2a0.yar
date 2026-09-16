rule TTP_XOR_MULT_DOSStub_c2a0 {
  strings:
    $key_c2a0 = { 96 c8 [2] e2 d0 [2] a5 d2 [2] e2 c3 [2] ac cf [2] a0 c5 [2] b7 ce [2] ac 80 [2] 91 }

  condition:
    any of them
}