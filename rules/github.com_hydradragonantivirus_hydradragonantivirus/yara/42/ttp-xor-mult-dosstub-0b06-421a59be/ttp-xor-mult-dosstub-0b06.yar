rule TTP_XOR_MULT_DOSStub_0b06 {
  strings:
    $key_0b06 = { 5f 6e [2] 2b 76 [2] 6c 74 [2] 2b 65 [2] 65 69 [2] 69 63 [2] 7e 68 [2] 65 26 [2] 58 }

  condition:
    any of them
}