rule TTP_XOR_MULT_DOSStub_1c66 {
  strings:
    $key_1c66 = { 48 0e [2] 3c 16 [2] 7b 14 [2] 3c 05 [2] 72 09 [2] 7e 03 [2] 69 08 [2] 72 46 [2] 4f }

  condition:
    any of them
}