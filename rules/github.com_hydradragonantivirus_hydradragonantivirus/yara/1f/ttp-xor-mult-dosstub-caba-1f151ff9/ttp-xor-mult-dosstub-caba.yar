rule TTP_XOR_MULT_DOSStub_caba {
  strings:
    $key_caba = { 9e d2 [2] ea ca [2] ad c8 [2] ea d9 [2] a4 d5 [2] a8 df [2] bf d4 [2] a4 9a [2] 99 }

  condition:
    any of them
}