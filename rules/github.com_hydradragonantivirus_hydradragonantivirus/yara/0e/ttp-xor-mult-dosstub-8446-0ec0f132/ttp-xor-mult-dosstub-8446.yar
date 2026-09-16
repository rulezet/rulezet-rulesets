rule TTP_XOR_MULT_DOSStub_8446 {
  strings:
    $key_8446 = { d0 2e [2] a4 36 [2] e3 34 [2] a4 25 [2] ea 29 [2] e6 23 [2] f1 28 [2] ea 66 [2] d7 }

  condition:
    any of them
}