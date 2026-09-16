rule TTP_XOR_MULT_DOSStub_5c66 {
  strings:
    $key_5c66 = { 08 0e [2] 7c 16 [2] 3b 14 [2] 7c 05 [2] 32 09 [2] 3e 03 [2] 29 08 [2] 32 46 [2] 0f }

  condition:
    any of them
}