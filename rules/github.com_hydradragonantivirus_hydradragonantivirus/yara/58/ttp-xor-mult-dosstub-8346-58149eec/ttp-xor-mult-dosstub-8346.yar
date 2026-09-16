rule TTP_XOR_MULT_DOSStub_8346 {
  strings:
    $key_8346 = { d7 2e [2] a3 36 [2] e4 34 [2] a3 25 [2] ed 29 [2] e1 23 [2] f6 28 [2] ed 66 [2] d0 }

  condition:
    any of them
}