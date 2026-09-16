rule TTP_XOR_MULT_DOSStub_4a70 {
  strings:
    $key_4a70 = { 1e 18 [2] 6a 00 [2] 2d 02 [2] 6a 13 [2] 24 1f [2] 28 15 [2] 3f 1e [2] 24 50 [2] 19 }

  condition:
    any of them
}