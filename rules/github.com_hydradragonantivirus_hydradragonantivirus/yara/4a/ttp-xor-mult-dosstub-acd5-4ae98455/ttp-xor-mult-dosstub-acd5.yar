rule TTP_XOR_MULT_DOSStub_acd5 {
  strings:
    $key_acd5 = { f8 bd [2] 8c a5 [2] cb a7 [2] 8c b6 [2] c2 ba [2] ce b0 [2] d9 bb [2] c2 f5 [2] ff }

  condition:
    any of them
}