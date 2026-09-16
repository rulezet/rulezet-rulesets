rule TTP_XOR_MULT_DOSStub_a5a9 {
  strings:
    $key_a5a9 = { f1 c1 [2] 85 d9 [2] c2 db [2] 85 ca [2] cb c6 [2] c7 cc [2] d0 c7 [2] cb 89 [2] f6 }

  condition:
    any of them
}