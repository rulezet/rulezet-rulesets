rule TTP_XOR_MULT_DOSStub_5c16 {
  strings:
    $key_5c16 = { 08 7e [2] 7c 66 [2] 3b 64 [2] 7c 75 [2] 32 79 [2] 3e 73 [2] 29 78 [2] 32 36 [2] 0f }

  condition:
    any of them
}