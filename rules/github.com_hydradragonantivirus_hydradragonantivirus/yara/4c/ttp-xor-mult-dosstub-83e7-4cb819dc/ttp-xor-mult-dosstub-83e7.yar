rule TTP_XOR_MULT_DOSStub_83e7 {
  strings:
    $key_83e7 = { d7 8f [2] a3 97 [2] e4 95 [2] a3 84 [2] ed 88 [2] e1 82 [2] f6 89 [2] ed c7 [2] d0 }

  condition:
    any of them
}