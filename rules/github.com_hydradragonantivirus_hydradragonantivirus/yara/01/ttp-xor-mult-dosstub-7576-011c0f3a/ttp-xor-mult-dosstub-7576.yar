rule TTP_XOR_MULT_DOSStub_7576 {
  strings:
    $key_7576 = { 21 1e [2] 55 06 [2] 12 04 [2] 55 15 [2] 1b 19 [2] 17 13 [2] 00 18 [2] 1b 56 [2] 26 }

  condition:
    any of them
}