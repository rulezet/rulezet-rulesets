rule TTP_XOR_MULT_DOSStub_5ce7 {
  strings:
    $key_5ce7 = { 08 8f [2] 7c 97 [2] 3b 95 [2] 7c 84 [2] 32 88 [2] 3e 82 [2] 29 89 [2] 32 c7 [2] 0f }

  condition:
    any of them
}