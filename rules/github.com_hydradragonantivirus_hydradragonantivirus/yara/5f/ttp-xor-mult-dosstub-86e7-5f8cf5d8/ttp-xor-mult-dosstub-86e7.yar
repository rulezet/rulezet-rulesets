rule TTP_XOR_MULT_DOSStub_86e7 {
  strings:
    $key_86e7 = { d2 8f [2] a6 97 [2] e1 95 [2] a6 84 [2] e8 88 [2] e4 82 [2] f3 89 [2] e8 c7 [2] d5 }

  condition:
    any of them
}