rule TTP_XOR_MULT_DOSStub_4eb2 {
  strings:
    $key_4eb2 = { 1a da [2] 6e c2 [2] 29 c0 [2] 6e d1 [2] 20 dd [2] 2c d7 [2] 3b dc [2] 20 92 [2] 1d }

  condition:
    any of them
}