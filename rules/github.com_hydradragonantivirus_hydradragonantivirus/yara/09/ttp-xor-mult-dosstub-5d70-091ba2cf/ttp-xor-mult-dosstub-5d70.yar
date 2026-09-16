rule TTP_XOR_MULT_DOSStub_5d70 {
  strings:
    $key_5d70 = { 09 18 [2] 7d 00 [2] 3a 02 [2] 7d 13 [2] 33 1f [2] 3f 15 [2] 28 1e [2] 33 50 [2] 0e }

  condition:
    any of them
}