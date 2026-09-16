rule TTP_XOR_MULT_DOSStub_7bba {
  strings:
    $key_7bba = { 2f d2 [2] 5b ca [2] 1c c8 [2] 5b d9 [2] 15 d5 [2] 19 df [2] 0e d4 [2] 15 9a [2] 28 }

  condition:
    any of them
}