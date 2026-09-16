rule TTP_XOR_MULT_DOSStub_7547 {
  strings:
    $key_7547 = { 21 2f [2] 55 37 [2] 12 35 [2] 55 24 [2] 1b 28 [2] 17 22 [2] 00 29 [2] 1b 67 [2] 26 }

  condition:
    any of them
}