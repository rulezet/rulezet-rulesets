rule TTP_XOR_MULT_DOSStub_acd1 {
  strings:
    $key_acd1 = { f8 b9 [2] 8c a1 [2] cb a3 [2] 8c b2 [2] c2 be [2] ce b4 [2] d9 bf [2] c2 f1 [2] ff }

  condition:
    any of them
}