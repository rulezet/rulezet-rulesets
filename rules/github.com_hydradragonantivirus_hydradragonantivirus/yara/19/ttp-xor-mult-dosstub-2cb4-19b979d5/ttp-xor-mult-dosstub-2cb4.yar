rule TTP_XOR_MULT_DOSStub_2cb4 {
  strings:
    $key_2cb4 = { 78 dc [2] 0c c4 [2] 4b c6 [2] 0c d7 [2] 42 db [2] 4e d1 [2] 59 da [2] 42 94 [2] 7f }

  condition:
    any of them
}