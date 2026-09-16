rule TTP_XOR_MULT_DOSStub_7eb1 {
  strings:
    $key_7eb1 = { 2a d9 [2] 5e c1 [2] 19 c3 [2] 5e d2 [2] 10 de [2] 1c d4 [2] 0b df [2] 10 91 [2] 2d }

  condition:
    any of them
}