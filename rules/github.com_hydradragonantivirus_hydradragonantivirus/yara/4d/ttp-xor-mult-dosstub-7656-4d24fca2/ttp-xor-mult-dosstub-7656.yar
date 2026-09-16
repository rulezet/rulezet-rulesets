rule TTP_XOR_MULT_DOSStub_7656 {
  strings:
    $key_7656 = { 22 3e [2] 56 26 [2] 11 24 [2] 56 35 [2] 18 39 [2] 14 33 [2] 03 38 [2] 18 76 [2] 25 }

  condition:
    any of them
}