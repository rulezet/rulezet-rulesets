rule TTP_XOR_MULT_DOSStub_c2b4 {
  strings:
    $key_c2b4 = { 96 dc [2] e2 c4 [2] a5 c6 [2] e2 d7 [2] ac db [2] a0 d1 [2] b7 da [2] ac 94 [2] 91 }

  condition:
    any of them
}