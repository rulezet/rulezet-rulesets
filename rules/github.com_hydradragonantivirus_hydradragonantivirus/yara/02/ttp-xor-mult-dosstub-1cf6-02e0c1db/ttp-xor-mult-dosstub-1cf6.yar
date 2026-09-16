rule TTP_XOR_MULT_DOSStub_1cf6 {
  strings:
    $key_1cf6 = { 48 9e [2] 3c 86 [2] 7b 84 [2] 3c 95 [2] 72 99 [2] 7e 93 [2] 69 98 [2] 72 d6 [2] 4f }

  condition:
    any of them
}