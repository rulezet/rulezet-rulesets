rule TTP_XOR_MULT_DOSStub_86e1 {
  strings:
    $key_86e1 = { d2 89 [2] a6 91 [2] e1 93 [2] a6 82 [2] e8 8e [2] e4 84 [2] f3 8f [2] e8 c1 [2] d5 }

  condition:
    any of them
}