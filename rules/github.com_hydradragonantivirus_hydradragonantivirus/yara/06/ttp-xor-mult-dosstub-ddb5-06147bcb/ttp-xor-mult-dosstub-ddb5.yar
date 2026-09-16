rule TTP_XOR_MULT_DOSStub_ddb5 {
  strings:
    $key_ddb5 = { 89 dd [2] fd c5 [2] ba c7 [2] fd d6 [2] b3 da [2] bf d0 [2] a8 db [2] b3 95 [2] 8e }

  condition:
    any of them
}