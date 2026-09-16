rule TTP_XOR_MULT_DOSStub_83e1 {
  strings:
    $key_83e1 = { d7 89 [2] a3 91 [2] e4 93 [2] a3 82 [2] ed 8e [2] e1 84 [2] f6 8f [2] ed c1 [2] d0 }

  condition:
    any of them
}