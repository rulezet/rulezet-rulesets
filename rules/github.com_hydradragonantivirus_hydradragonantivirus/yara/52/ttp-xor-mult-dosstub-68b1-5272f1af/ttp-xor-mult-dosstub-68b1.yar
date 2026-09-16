rule TTP_XOR_MULT_DOSStub_68b1 {
  strings:
    $key_68b1 = { 3c d9 [2] 48 c1 [2] 0f c3 [2] 48 d2 [2] 06 de [2] 0a d4 [2] 1d df [2] 06 91 [2] 3b }

  condition:
    any of them
}