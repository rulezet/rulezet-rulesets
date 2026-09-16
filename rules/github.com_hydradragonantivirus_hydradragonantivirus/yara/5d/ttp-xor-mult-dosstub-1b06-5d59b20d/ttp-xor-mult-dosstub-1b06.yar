rule TTP_XOR_MULT_DOSStub_1b06 {
  strings:
    $key_1b06 = { 4f 6e [2] 3b 76 [2] 7c 74 [2] 3b 65 [2] 75 69 [2] 79 63 [2] 6e 68 [2] 75 26 [2] 48 }

  condition:
    any of them
}