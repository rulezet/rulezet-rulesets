rule TTP_XOR_MULT_DOSStub_1eb2 {
  strings:
    $key_1eb2 = { 4a da [2] 3e c2 [2] 79 c0 [2] 3e d1 [2] 70 dd [2] 7c d7 [2] 6b dc [2] 70 92 [2] 4d }

  condition:
    any of them
}