rule TTP_XOR_MULT_DOSStub_1cb2 {
  strings:
    $key_1cb2 = { 48 da [2] 3c c2 [2] 7b c0 [2] 3c d1 [2] 72 dd [2] 7e d7 [2] 69 dc [2] 72 92 [2] 4f }

  condition:
    any of them
}