rule TTP_XOR_MULT_DOSStub_acd3 {
  strings:
    $key_acd3 = { f8 bb [2] 8c a3 [2] cb a1 [2] 8c b0 [2] c2 bc [2] ce b6 [2] d9 bd [2] c2 f3 [2] ff }

  condition:
    any of them
}