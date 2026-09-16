rule TTP_XOR_MULT_DOSStub_8457 {
  strings:
    $key_8457 = { d0 3f [2] a4 27 [2] e3 25 [2] a4 34 [2] ea 38 [2] e6 32 [2] f1 39 [2] ea 77 [2] d7 }

  condition:
    any of them
}