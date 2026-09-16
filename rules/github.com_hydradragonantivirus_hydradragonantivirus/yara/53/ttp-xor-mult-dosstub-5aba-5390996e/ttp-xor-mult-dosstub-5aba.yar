rule TTP_XOR_MULT_DOSStub_5aba {
  strings:
    $key_5aba = { 0e d2 [2] 7a ca [2] 3d c8 [2] 7a d9 [2] 34 d5 [2] 38 df [2] 2f d4 [2] 34 9a [2] 09 }

  condition:
    any of them
}