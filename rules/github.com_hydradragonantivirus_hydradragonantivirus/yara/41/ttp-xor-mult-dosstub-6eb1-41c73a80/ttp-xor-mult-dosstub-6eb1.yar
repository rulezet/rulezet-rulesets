rule TTP_XOR_MULT_DOSStub_6eb1 {
  strings:
    $key_6eb1 = { 3a d9 [2] 4e c1 [2] 09 c3 [2] 4e d2 [2] 00 de [2] 0c d4 [2] 1b df [2] 00 91 [2] 3d }

  condition:
    any of them
}