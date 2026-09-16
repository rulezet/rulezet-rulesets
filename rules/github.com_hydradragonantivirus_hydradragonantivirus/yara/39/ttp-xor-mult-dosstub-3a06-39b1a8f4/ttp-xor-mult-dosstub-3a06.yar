rule TTP_XOR_MULT_DOSStub_3a06 {
  strings:
    $key_3a06 = { 6e 6e [2] 1a 76 [2] 5d 74 [2] 1a 65 [2] 54 69 [2] 58 63 [2] 4f 68 [2] 54 26 [2] 69 }

  condition:
    any of them
}