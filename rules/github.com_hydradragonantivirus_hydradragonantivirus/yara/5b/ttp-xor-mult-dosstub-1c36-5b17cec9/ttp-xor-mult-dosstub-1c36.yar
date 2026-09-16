rule TTP_XOR_MULT_DOSStub_1c36 {
  strings:
    $key_1c36 = { 48 5e [2] 3c 46 [2] 7b 44 [2] 3c 55 [2] 72 59 [2] 7e 53 [2] 69 58 [2] 72 16 [2] 4f }

  condition:
    any of them
}