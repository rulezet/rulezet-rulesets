rule TTP_XOR_MULT_DOSStub_1cf0 {
  strings:
    $key_1cf0 = { 48 98 [2] 3c 80 [2] 7b 82 [2] 3c 93 [2] 72 9f [2] 7e 95 [2] 69 9e [2] 72 d0 [2] 4f }

  condition:
    any of them
}