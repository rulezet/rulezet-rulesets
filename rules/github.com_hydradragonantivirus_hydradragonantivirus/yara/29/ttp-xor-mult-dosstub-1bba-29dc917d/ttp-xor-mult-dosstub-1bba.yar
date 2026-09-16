rule TTP_XOR_MULT_DOSStub_1bba {
  strings:
    $key_1bba = { 4f d2 [2] 3b ca [2] 7c c8 [2] 3b d9 [2] 75 d5 [2] 79 df [2] 6e d4 [2] 75 9a [2] 48 }

  condition:
    any of them
}