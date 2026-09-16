rule TTP_XOR_MULT_DOSStub_1270 {
  strings:
    $key_1270 = { 46 18 [2] 32 00 [2] 75 02 [2] 32 13 [2] 7c 1f [2] 70 15 [2] 67 1e [2] 7c 50 [2] 41 }

  condition:
    any of them
}