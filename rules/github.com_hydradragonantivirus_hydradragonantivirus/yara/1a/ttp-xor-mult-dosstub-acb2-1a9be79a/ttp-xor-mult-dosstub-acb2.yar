rule TTP_XOR_MULT_DOSStub_acb2 {
  strings:
    $key_acb2 = { f8 da [2] 8c c2 [2] cb c0 [2] 8c d1 [2] c2 dd [2] ce d7 [2] d9 dc [2] c2 92 [2] ff }

  condition:
    any of them
}