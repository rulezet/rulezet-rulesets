rule TTP_XOR_MULT_DOSStub_7511 {
  strings:
    $key_7511 = { 21 79 [2] 55 61 [2] 12 63 [2] 55 72 [2] 1b 7e [2] 17 74 [2] 00 7f [2] 1b 31 [2] 26 }

  condition:
    any of them
}