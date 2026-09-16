rule TTP_XOR_MULT_DOSStub_4b06 {
  strings:
    $key_4b06 = { 1f 6e [2] 6b 76 [2] 2c 74 [2] 6b 65 [2] 25 69 [2] 29 63 [2] 3e 68 [2] 25 26 [2] 18 }

  condition:
    any of them
}