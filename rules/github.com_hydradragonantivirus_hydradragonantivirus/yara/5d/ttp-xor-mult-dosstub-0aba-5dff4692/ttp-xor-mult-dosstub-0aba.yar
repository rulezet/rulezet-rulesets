rule TTP_XOR_MULT_DOSStub_0aba {
  strings:
    $key_0aba = { 5e d2 [2] 2a ca [2] 6d c8 [2] 2a d9 [2] 64 d5 [2] 68 df [2] 7f d4 [2] 64 9a [2] 59 }

  condition:
    any of them
}