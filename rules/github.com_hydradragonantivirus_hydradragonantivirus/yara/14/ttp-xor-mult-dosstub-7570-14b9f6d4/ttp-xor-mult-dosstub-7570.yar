rule TTP_XOR_MULT_DOSStub_7570 {
  strings:
    $key_7570 = { 21 18 [2] 55 00 [2] 12 02 [2] 55 13 [2] 1b 1f [2] 17 15 [2] 00 1e [2] 1b 50 [2] 26 }

  condition:
    any of them
}