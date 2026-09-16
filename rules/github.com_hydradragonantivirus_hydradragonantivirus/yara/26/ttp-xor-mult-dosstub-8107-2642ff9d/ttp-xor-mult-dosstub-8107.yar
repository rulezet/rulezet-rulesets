rule TTP_XOR_MULT_DOSStub_8107 {
  strings:
    $key_8107 = { d5 6f [2] a1 77 [2] e6 75 [2] a1 64 [2] ef 68 [2] e3 62 [2] f4 69 [2] ef 27 [2] d2 }

  condition:
    any of them
}