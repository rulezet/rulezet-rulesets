rule TTP_XOR_MULT_DOSStub_acd4 {
  strings:
    $key_acd4 = { f8 bc [2] 8c a4 [2] cb a6 [2] 8c b7 [2] c2 bb [2] ce b1 [2] d9 ba [2] c2 f4 [2] ff }

  condition:
    any of them
}