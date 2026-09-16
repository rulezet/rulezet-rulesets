rule TTP_XOR_MULT_DOSStub_a5ad {
  strings:
    $key_a5ad = { f1 c5 [2] 85 dd [2] c2 df [2] 85 ce [2] cb c2 [2] c7 c8 [2] d0 c3 [2] cb 8d [2] f6 }

  condition:
    any of them
}