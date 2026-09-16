rule TTP_XOR_MULT_DOSStub_83b2 {
  strings:
    $key_83b2 = { d7 da [2] a3 c2 [2] e4 c0 [2] a3 d1 [2] ed dd [2] e1 d7 [2] f6 dc [2] ed 92 [2] d0 }

  condition:
    any of them
}