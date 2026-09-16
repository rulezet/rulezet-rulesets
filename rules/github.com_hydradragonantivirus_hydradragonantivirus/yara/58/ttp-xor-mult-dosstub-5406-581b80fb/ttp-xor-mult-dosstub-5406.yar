rule TTP_XOR_MULT_DOSStub_5406 {
  strings:
    $key_5406 = { 00 6e [2] 74 76 [2] 33 74 [2] 74 65 [2] 3a 69 [2] 36 63 [2] 21 68 [2] 3a 26 [2] 07 }

  condition:
    any of them
}