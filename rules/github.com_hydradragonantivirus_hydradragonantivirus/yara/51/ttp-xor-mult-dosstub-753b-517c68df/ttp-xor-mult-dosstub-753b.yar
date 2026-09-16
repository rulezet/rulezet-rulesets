rule TTP_XOR_MULT_DOSStub_753b {
  strings:
    $key_753b = { 21 53 [2] 55 4b [2] 12 49 [2] 55 58 [2] 1b 54 [2] 17 5e [2] 00 55 [2] 1b 1b [2] 26 }

  condition:
    any of them
}