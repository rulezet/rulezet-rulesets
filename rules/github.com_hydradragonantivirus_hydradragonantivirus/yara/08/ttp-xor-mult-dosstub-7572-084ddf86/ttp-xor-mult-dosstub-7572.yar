rule TTP_XOR_MULT_DOSStub_7572 {
  strings:
    $key_7572 = { 21 1a [2] 55 02 [2] 12 00 [2] 55 11 [2] 1b 1d [2] 17 17 [2] 00 1c [2] 1b 52 [2] 26 }

  condition:
    any of them
}