rule TTP_XOR_MULT_DOSStub_7406 {
  strings:
    $key_7406 = { 20 6e [2] 54 76 [2] 13 74 [2] 54 65 [2] 1a 69 [2] 16 63 [2] 01 68 [2] 1a 26 [2] 27 }

  condition:
    any of them
}