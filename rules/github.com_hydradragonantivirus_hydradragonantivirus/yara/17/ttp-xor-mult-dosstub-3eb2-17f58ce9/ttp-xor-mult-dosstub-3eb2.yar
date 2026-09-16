rule TTP_XOR_MULT_DOSStub_3eb2 {
  strings:
    $key_3eb2 = { 6a da [2] 1e c2 [2] 59 c0 [2] 1e d1 [2] 50 dd [2] 5c d7 [2] 4b dc [2] 50 92 [2] 6d }

  condition:
    any of them
}