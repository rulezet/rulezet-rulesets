rule TTP_XOR_MULT_DOSStub_5070 {
  strings:
    $key_5070 = { 04 18 [2] 70 00 [2] 37 02 [2] 70 13 [2] 3e 1f [2] 32 15 [2] 25 1e [2] 3e 50 [2] 03 }

  condition:
    any of them
}