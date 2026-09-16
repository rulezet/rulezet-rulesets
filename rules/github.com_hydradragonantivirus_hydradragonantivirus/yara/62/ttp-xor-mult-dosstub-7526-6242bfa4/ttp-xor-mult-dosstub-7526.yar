rule TTP_XOR_MULT_DOSStub_7526 {
  strings:
    $key_7526 = { 21 4e [2] 55 56 [2] 12 54 [2] 55 45 [2] 1b 49 [2] 17 43 [2] 00 48 [2] 1b 06 [2] 26 }

  condition:
    any of them
}