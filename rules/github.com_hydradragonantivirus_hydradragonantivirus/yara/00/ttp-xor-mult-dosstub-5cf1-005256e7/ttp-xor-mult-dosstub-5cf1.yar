rule TTP_XOR_MULT_DOSStub_5cf1 {
  strings:
    $key_5cf1 = { 08 99 [2] 7c 81 [2] 3b 83 [2] 7c 92 [2] 32 9e [2] 3e 94 [2] 29 9f [2] 32 d1 [2] 0f }

  condition:
    any of them
}