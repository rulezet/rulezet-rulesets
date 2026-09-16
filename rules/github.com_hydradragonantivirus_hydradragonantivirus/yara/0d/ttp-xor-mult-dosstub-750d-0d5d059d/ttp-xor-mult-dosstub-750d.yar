rule TTP_XOR_MULT_DOSStub_750d {
  strings:
    $key_750d = { 21 65 [2] 55 7d [2] 12 7f [2] 55 6e [2] 1b 62 [2] 17 68 [2] 00 63 [2] 1b 2d [2] 26 }

  condition:
    any of them
}