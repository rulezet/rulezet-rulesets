rule TTP_XOR_MULT_DOSStub_2247 {
  strings:
    $key_2247 = { 76 2f [2] 02 37 [2] 45 35 [2] 02 24 [2] 4c 28 [2] 40 22 [2] 57 29 [2] 4c 67 [2] 71 }

  condition:
    any of them
}