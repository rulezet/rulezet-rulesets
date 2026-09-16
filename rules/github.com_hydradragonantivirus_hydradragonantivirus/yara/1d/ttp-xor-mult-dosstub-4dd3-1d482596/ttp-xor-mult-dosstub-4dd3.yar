rule TTP_XOR_MULT_DOSStub_4dd3 {
  strings:
    $key_4dd3 = { 19 bb [2] 6d a3 [2] 2a a1 [2] 6d b0 [2] 23 bc [2] 2f b6 [2] 38 bd [2] 23 f3 [2] 1e }

  condition:
    any of them
}