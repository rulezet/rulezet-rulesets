rule TTP_XOR_MULT_DOSStub_3bb7 {
  strings:
    $key_3bb7 = { 6f df [2] 1b c7 [2] 5c c5 [2] 1b d4 [2] 55 d8 [2] 59 d2 [2] 4e d9 [2] 55 97 [2] 68 }

  condition:
    any of them
}