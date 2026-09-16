rule TTP_XOR_MULT_DOSStub_750a {
  strings:
    $key_750a = { 21 62 [2] 55 7a [2] 12 78 [2] 55 69 [2] 1b 65 [2] 17 6f [2] 00 64 [2] 1b 2a [2] 26 }

  condition:
    any of them
}