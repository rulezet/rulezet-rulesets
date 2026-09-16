rule TTP_XOR_MULT_DOSStub_5bb7 {
  strings:
    $key_5bb7 = { 0f df [2] 7b c7 [2] 3c c5 [2] 7b d4 [2] 35 d8 [2] 39 d2 [2] 2e d9 [2] 35 97 [2] 08 }

  condition:
    any of them
}