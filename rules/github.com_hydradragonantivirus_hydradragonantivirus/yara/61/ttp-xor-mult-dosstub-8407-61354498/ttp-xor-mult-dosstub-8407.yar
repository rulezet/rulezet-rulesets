rule TTP_XOR_MULT_DOSStub_8407 {
  strings:
    $key_8407 = { d0 6f [2] a4 77 [2] e3 75 [2] a4 64 [2] ea 68 [2] e6 62 [2] f1 69 [2] ea 27 [2] d7 }

  condition:
    any of them
}