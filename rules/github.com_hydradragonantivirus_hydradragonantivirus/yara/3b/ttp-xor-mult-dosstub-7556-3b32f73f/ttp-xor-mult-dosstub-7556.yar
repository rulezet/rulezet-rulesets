rule TTP_XOR_MULT_DOSStub_7556 {
  strings:
    $key_7556 = { 21 3e [2] 55 26 [2] 12 24 [2] 55 35 [2] 1b 39 [2] 17 33 [2] 00 38 [2] 1b 76 [2] 26 }

  condition:
    any of them
}