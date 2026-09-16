rule TTP_XOR_MULT_DOSStub_6247 {
  strings:
    $key_6247 = { 36 2f [2] 42 37 [2] 05 35 [2] 42 24 [2] 0c 28 [2] 00 22 [2] 17 29 [2] 0c 67 [2] 31 }

  condition:
    any of them
}