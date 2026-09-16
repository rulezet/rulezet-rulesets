rule TTP_XOR_MULT_DOSStub_1a70 {
  strings:
    $key_1a70 = { 4e 18 [2] 3a 00 [2] 7d 02 [2] 3a 13 [2] 74 1f [2] 78 15 [2] 6f 1e [2] 74 50 [2] 49 }

  condition:
    any of them
}