rule TTP_XOR_MULT_DOSStub_1cf7 {
  strings:
    $key_1cf7 = { 48 9f [2] 3c 87 [2] 7b 85 [2] 3c 94 [2] 72 98 [2] 7e 92 [2] 69 99 [2] 72 d7 [2] 4f }

  condition:
    any of them
}