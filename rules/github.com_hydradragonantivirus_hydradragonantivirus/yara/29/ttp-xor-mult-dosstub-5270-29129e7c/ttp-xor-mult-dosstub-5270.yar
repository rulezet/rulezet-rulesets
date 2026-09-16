rule TTP_XOR_MULT_DOSStub_5270 {
  strings:
    $key_5270 = { 06 18 [2] 72 00 [2] 35 02 [2] 72 13 [2] 3c 1f [2] 30 15 [2] 27 1e [2] 3c 50 [2] 01 }

  condition:
    any of them
}