rule TTP_XOR_MULT_DOSStub_8436 {
  strings:
    $key_8436 = { d0 5e [2] a4 46 [2] e3 44 [2] a4 55 [2] ea 59 [2] e6 53 [2] f1 58 [2] ea 16 [2] d7 }

  condition:
    any of them
}