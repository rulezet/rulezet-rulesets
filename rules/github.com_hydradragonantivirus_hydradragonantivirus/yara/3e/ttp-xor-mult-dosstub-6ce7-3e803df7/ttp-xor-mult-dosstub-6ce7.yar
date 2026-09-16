rule TTP_XOR_MULT_DOSStub_6ce7 {
  strings:
    $key_6ce7 = { 38 8f [2] 4c 97 [2] 0b 95 [2] 4c 84 [2] 02 88 [2] 0e 82 [2] 19 89 [2] 02 c7 [2] 3f }

  condition:
    any of them
}