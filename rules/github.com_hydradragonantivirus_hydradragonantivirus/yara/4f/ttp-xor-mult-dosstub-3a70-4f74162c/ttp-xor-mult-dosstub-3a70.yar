rule TTP_XOR_MULT_DOSStub_3a70 {
  strings:
    $key_3a70 = { 6e 18 [2] 1a 00 [2] 5d 02 [2] 1a 13 [2] 54 1f [2] 58 15 [2] 4f 1e [2] 54 50 [2] 69 }

  condition:
    any of them
}