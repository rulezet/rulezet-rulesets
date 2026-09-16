rule TTP_XOR_MULT_DOSStub_83b3 {
  strings:
    $key_83b3 = { d7 db [2] a3 c3 [2] e4 c1 [2] a3 d0 [2] ed dc [2] e1 d6 [2] f6 dd [2] ed 93 [2] d0 }

  condition:
    any of them
}