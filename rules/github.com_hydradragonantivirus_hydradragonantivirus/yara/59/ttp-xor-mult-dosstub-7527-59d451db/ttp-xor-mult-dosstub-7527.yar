rule TTP_XOR_MULT_DOSStub_7527 {
  strings:
    $key_7527 = { 21 4f [2] 55 57 [2] 12 55 [2] 55 44 [2] 1b 48 [2] 17 42 [2] 00 49 [2] 1b 07 [2] 26 }

  condition:
    any of them
}