rule TTP_XOR_MULT_DOSStub_83fa {
  strings:
    $key_83fa = { d7 92 [2] a3 8a [2] e4 88 [2] a3 99 [2] ed 95 [2] e1 9f [2] f6 94 [2] ed da [2] d0 }

  condition:
    any of them
}