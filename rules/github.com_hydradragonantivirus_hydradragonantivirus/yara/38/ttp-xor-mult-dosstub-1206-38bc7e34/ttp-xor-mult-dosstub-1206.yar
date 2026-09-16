rule TTP_XOR_MULT_DOSStub_1206 {
  strings:
    $key_1206 = { 46 6e [2] 32 76 [2] 75 74 [2] 32 65 [2] 7c 69 [2] 70 63 [2] 67 68 [2] 7c 26 [2] 41 }

  condition:
    any of them
}