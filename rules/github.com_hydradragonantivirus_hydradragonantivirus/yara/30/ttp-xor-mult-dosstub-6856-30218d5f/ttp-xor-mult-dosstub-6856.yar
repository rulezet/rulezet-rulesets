rule TTP_XOR_MULT_DOSStub_6856 {
  strings:
    $key_6856 = { 3c 3e [2] 48 26 [2] 0f 24 [2] 48 35 [2] 06 39 [2] 0a 33 [2] 1d 38 [2] 06 76 [2] 3b }

  condition:
    any of them
}