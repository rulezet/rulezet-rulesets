rule TTP_XOR_MULT_DOSStub_1c47 {
  strings:
    $key_1c47 = { 48 2f [2] 3c 37 [2] 7b 35 [2] 3c 24 [2] 72 28 [2] 7e 22 [2] 69 29 [2] 72 67 [2] 4f }

  condition:
    any of them
}