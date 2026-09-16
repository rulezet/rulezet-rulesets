rule TTP_XOR_MULT_DOSStub_6106 {
  strings:
    $key_6106 = { 35 6e [2] 41 76 [2] 06 74 [2] 41 65 [2] 0f 69 [2] 03 63 [2] 14 68 [2] 0f 26 [2] 32 }

  condition:
    any of them
}