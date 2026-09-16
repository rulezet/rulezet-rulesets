rule TTP_XOR_MULT_DOSStub_23ca {
  strings:
    $key_23ca = { 77 a2 [2] 03 ba [2] 44 b8 [2] 03 a9 [2] 4d a5 [2] 41 af [2] 56 a4 [2] 4d ea [2] 70 }

  condition:
    any of them
}