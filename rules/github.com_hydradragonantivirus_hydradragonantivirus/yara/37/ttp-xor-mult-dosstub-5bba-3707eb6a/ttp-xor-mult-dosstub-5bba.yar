rule TTP_XOR_MULT_DOSStub_5bba {
  strings:
    $key_5bba = { 0f d2 [2] 7b ca [2] 3c c8 [2] 7b d9 [2] 35 d5 [2] 39 df [2] 2e d4 [2] 35 9a [2] 08 }

  condition:
    any of them
}