rule TTP_XOR_MULT_DOSStub_1c17 {
  strings:
    $key_1c17 = { 48 7f [2] 3c 67 [2] 7b 65 [2] 3c 74 [2] 72 78 [2] 7e 72 [2] 69 79 [2] 72 37 [2] 4f }

  condition:
    any of them
}