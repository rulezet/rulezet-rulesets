rule TTP_XOR_MULT_DOSStub_ddb4 {
  strings:
    $key_ddb4 = { 89 dc [2] fd c4 [2] ba c6 [2] fd d7 [2] b3 db [2] bf d1 [2] a8 da [2] b3 94 [2] 8e }

  condition:
    any of them
}