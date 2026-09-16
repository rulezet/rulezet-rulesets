rule TTP_XOR_MULT_DOSStub_83e6 {
  strings:
    $key_83e6 = { d7 8e [2] a3 96 [2] e4 94 [2] a3 85 [2] ed 89 [2] e1 83 [2] f6 88 [2] ed c6 [2] d0 }

  condition:
    any of them
}