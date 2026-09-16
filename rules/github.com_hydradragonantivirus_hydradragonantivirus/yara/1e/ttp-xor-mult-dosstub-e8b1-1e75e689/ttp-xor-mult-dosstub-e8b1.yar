rule TTP_XOR_MULT_DOSStub_e8b1 {
  strings:
    $key_e8b1 = { bc d9 [2] c8 c1 [2] 8f c3 [2] c8 d2 [2] 86 de [2] 8a d4 [2] 9d df [2] 86 91 [2] bb }

  condition:
    any of them
}