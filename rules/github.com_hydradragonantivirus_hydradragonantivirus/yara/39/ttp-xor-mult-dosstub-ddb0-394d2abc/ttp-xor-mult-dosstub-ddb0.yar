rule TTP_XOR_MULT_DOSStub_ddb0 {
  strings:
    $key_ddb0 = { 89 d8 [2] fd c0 [2] ba c2 [2] fd d3 [2] b3 df [2] bf d5 [2] a8 de [2] b3 90 [2] 8e }

  condition:
    any of them
}