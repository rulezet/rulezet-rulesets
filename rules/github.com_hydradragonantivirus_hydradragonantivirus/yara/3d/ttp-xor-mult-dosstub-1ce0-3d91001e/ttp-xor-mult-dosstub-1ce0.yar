rule TTP_XOR_MULT_DOSStub_1ce0 {
  strings:
    $key_1ce0 = { 48 88 [2] 3c 90 [2] 7b 92 [2] 3c 83 [2] 72 8f [2] 7e 85 [2] 69 8e [2] 72 c0 [2] 4f }

  condition:
    any of them
}