rule TTP_XOR_MULT_DOSStub_1c60 {
  strings:
    $key_1c60 = { 48 08 [2] 3c 10 [2] 7b 12 [2] 3c 03 [2] 72 0f [2] 7e 05 [2] 69 0e [2] 72 40 [2] 4f }

  condition:
    any of them
}