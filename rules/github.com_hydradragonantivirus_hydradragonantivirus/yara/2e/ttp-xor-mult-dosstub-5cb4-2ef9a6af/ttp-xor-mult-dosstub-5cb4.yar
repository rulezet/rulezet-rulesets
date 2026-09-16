rule TTP_XOR_MULT_DOSStub_5cb4 {
  strings:
    $key_5cb4 = { 08 dc [2] 7c c4 [2] 3b c6 [2] 7c d7 [2] 32 db [2] 3e d1 [2] 29 da [2] 32 94 [2] 0f }

  condition:
    any of them
}