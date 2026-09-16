rule TTP_XOR_MULT_DOSStub_1c16 {
  strings:
    $key_1c16 = { 48 7e [2] 3c 66 [2] 7b 64 [2] 3c 75 [2] 72 79 [2] 7e 73 [2] 69 78 [2] 72 36 [2] 4f }

  condition:
    any of them
}