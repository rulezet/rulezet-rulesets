rule TTP_XOR_MULT_DOSStub_8406 {
  strings:
    $key_8406 = { d0 6e [2] a4 76 [2] e3 74 [2] a4 65 [2] ea 69 [2] e6 63 [2] f1 68 [2] ea 26 [2] d7 }

  condition:
    any of them
}