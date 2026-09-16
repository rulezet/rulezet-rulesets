rule TTP_XOR_MULT_DOSStub_1247 {
  strings:
    $key_1247 = { 46 2f [2] 32 37 [2] 75 35 [2] 32 24 [2] 7c 28 [2] 70 22 [2] 67 29 [2] 7c 67 [2] 41 }

  condition:
    any of them
}