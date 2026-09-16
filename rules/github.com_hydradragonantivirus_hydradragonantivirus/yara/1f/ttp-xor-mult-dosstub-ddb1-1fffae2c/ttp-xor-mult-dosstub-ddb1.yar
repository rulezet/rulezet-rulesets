rule TTP_XOR_MULT_DOSStub_ddb1 {
  strings:
    $key_ddb1 = { 89 d9 [2] fd c1 [2] ba c3 [2] fd d2 [2] b3 de [2] bf d4 [2] a8 df [2] b3 91 [2] 8e }

  condition:
    any of them
}