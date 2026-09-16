rule TTP_XOR_MULT_DOSStub_acb5 {
  strings:
    $key_acb5 = { f8 dd [2] 8c c5 [2] cb c7 [2] 8c d6 [2] c2 da [2] ce d0 [2] d9 db [2] c2 95 [2] ff }

  condition:
    any of them
}