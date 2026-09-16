rule TTP_XOR_MULT_DOSStub_86b3 {
  strings:
    $key_86b3 = { d2 db [2] a6 c3 [2] e1 c1 [2] a6 d0 [2] e8 dc [2] e4 d6 [2] f3 dd [2] e8 93 [2] d5 }

  condition:
    any of them
}