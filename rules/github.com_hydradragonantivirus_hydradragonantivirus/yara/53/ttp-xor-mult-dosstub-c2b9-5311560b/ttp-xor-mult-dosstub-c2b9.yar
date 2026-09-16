rule TTP_XOR_MULT_DOSStub_c2b9 {
  strings:
    $key_c2b9 = { 96 d1 [2] e2 c9 [2] a5 cb [2] e2 da [2] ac d6 [2] a0 dc [2] b7 d7 [2] ac 99 [2] 91 }

  condition:
    any of them
}