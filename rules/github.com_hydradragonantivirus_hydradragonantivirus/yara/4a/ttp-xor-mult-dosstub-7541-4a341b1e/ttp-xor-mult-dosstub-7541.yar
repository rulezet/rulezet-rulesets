rule TTP_XOR_MULT_DOSStub_7541 {
  strings:
    $key_7541 = { 21 29 [2] 55 31 [2] 12 33 [2] 55 22 [2] 1b 2e [2] 17 24 [2] 00 2f [2] 1b 61 [2] 26 }

  condition:
    any of them
}