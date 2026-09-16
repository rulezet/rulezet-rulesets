rule TTP_XOR_MULT_DOSStub_83b5 {
  strings:
    $key_83b5 = { d7 dd [2] a3 c5 [2] e4 c7 [2] a3 d6 [2] ed da [2] e1 d0 [2] f6 db [2] ed 95 [2] d0 }

  condition:
    any of them
}