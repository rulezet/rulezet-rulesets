rule TTP_XOR_MULT_DOSStub_750b {
  strings:
    $key_750b = { 21 63 [2] 55 7b [2] 12 79 [2] 55 68 [2] 1b 64 [2] 17 6e [2] 00 65 [2] 1b 2b [2] 26 }

  condition:
    any of them
}