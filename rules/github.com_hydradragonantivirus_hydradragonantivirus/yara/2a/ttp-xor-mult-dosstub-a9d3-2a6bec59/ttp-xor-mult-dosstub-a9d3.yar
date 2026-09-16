rule TTP_XOR_MULT_DOSStub_a9d3 {
  strings:
    $key_a9d3 = { fd bb [2] 89 a3 [2] ce a1 [2] 89 b0 [2] c7 bc [2] cb b6 [2] dc bd [2] c7 f3 [2] fa }

  condition:
    any of them
}