rule TTP_XOR_MULT_DOSStub_4606 {
  strings:
    $key_4606 = { 12 6e [2] 66 76 [2] 21 74 [2] 66 65 [2] 28 69 [2] 24 63 [2] 33 68 [2] 28 26 [2] 15 }

  condition:
    any of them
}