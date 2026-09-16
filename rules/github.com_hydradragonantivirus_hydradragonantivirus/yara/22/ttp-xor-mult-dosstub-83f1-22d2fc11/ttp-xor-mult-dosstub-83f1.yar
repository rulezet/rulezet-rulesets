rule TTP_XOR_MULT_DOSStub_83f1 {
  strings:
    $key_83f1 = { d7 99 [2] a3 81 [2] e4 83 [2] a3 92 [2] ed 9e [2] e1 94 [2] f6 9f [2] ed d1 [2] d0 }

  condition:
    any of them
}