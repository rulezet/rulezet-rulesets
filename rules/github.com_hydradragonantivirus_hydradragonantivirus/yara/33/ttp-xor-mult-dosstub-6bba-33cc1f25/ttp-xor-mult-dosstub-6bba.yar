rule TTP_XOR_MULT_DOSStub_6bba {
  strings:
    $key_6bba = { 3f d2 [2] 4b ca [2] 0c c8 [2] 4b d9 [2] 05 d5 [2] 09 df [2] 1e d4 [2] 05 9a [2] 38 }

  condition:
    any of them
}