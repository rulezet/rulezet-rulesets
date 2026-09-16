rule TTP_XOR_MULT_DOSStub_1c06 {
  strings:
    $key_1c06 = { 48 6e [2] 3c 76 [2] 7b 74 [2] 3c 65 [2] 72 69 [2] 7e 63 [2] 69 68 [2] 72 26 [2] 4f }

  condition:
    any of them
}