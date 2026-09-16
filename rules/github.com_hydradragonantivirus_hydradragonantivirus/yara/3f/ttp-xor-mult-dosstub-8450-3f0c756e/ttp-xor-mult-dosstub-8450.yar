rule TTP_XOR_MULT_DOSStub_8450 {
  strings:
    $key_8450 = { d0 38 [2] a4 20 [2] e3 22 [2] a4 33 [2] ea 3f [2] e6 35 [2] f1 3e [2] ea 70 [2] d7 }

  condition:
    any of them
}