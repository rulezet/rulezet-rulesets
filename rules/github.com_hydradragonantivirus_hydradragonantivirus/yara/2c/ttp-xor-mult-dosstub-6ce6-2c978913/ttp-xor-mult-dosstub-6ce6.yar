rule TTP_XOR_MULT_DOSStub_6ce6 {
  strings:
    $key_6ce6 = { 38 8e [2] 4c 96 [2] 0b 94 [2] 4c 85 [2] 02 89 [2] 0e 83 [2] 19 88 [2] 02 c6 [2] 3f }

  condition:
    any of them
}