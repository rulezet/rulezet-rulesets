rule TTP_XOR_MULT_DOSStub_1ce6 {
  strings:
    $key_1ce6 = { 48 8e [2] 3c 96 [2] 7b 94 [2] 3c 85 [2] 72 89 [2] 7e 83 [2] 69 88 [2] 72 c6 [2] 4f }

  condition:
    any of them
}