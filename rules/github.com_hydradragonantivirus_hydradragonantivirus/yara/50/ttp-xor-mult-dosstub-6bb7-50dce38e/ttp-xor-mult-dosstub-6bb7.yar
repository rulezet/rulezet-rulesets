rule TTP_XOR_MULT_DOSStub_6bb7 {
  strings:
    $key_6bb7 = { 3f df [2] 4b c7 [2] 0c c5 [2] 4b d4 [2] 05 d8 [2] 09 d2 [2] 1e d9 [2] 05 97 [2] 38 }

  condition:
    any of them
}