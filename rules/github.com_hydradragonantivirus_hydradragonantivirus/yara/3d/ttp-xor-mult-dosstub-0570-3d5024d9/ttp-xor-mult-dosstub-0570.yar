rule TTP_XOR_MULT_DOSStub_0570 {
  strings:
    $key_0570 = { 51 18 [2] 25 00 [2] 62 02 [2] 25 13 [2] 6b 1f [2] 67 15 [2] 70 1e [2] 6b 50 [2] 56 }

  condition:
    any of them
}