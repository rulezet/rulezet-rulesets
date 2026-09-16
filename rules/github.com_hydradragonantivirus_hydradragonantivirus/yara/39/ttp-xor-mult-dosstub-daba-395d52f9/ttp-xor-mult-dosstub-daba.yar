rule TTP_XOR_MULT_DOSStub_daba {
  strings:
    $key_daba = { 8e d2 [2] fa ca [2] bd c8 [2] fa d9 [2] b4 d5 [2] b8 df [2] af d4 [2] b4 9a [2] 89 }

  condition:
    any of them
}