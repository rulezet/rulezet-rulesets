rule TTP_XOR_MULT_DOSStub_18b1 {
  strings:
    $key_18b1 = { 4c d9 [2] 38 c1 [2] 7f c3 [2] 38 d2 [2] 76 de [2] 7a d4 [2] 6d df [2] 76 91 [2] 4b }

  condition:
    any of them
}