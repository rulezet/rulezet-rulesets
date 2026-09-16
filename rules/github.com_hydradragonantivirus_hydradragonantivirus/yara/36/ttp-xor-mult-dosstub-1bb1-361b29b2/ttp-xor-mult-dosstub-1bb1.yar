rule TTP_XOR_MULT_DOSStub_1bb1 {
  strings:
    $key_1bb1 = { 4f d9 [2] 3b c1 [2] 7c c3 [2] 3b d2 [2] 75 de [2] 79 d4 [2] 6e df [2] 75 91 [2] 48 }

  condition:
    any of them
}