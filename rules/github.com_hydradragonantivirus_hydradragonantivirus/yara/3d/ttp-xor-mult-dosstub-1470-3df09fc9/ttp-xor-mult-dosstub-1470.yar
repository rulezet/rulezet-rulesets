rule TTP_XOR_MULT_DOSStub_1470 {
  strings:
    $key_1470 = { 40 18 [2] 34 00 [2] 73 02 [2] 34 13 [2] 7a 1f [2] 76 15 [2] 61 1e [2] 7a 50 [2] 47 }

  condition:
    any of them
}