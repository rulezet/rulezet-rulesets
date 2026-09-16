rule TTP_XOR_MULT_DOSStub_5b06 {
  strings:
    $key_5b06 = { 0f 6e [2] 7b 76 [2] 3c 74 [2] 7b 65 [2] 35 69 [2] 39 63 [2] 2e 68 [2] 35 26 [2] 08 }

  condition:
    any of them
}