rule TTP_XOR_MULT_DOSStub_5dd3 {
  strings:
    $key_5dd3 = { 09 bb [2] 7d a3 [2] 3a a1 [2] 7d b0 [2] 33 bc [2] 3f b6 [2] 28 bd [2] 33 f3 [2] 0e }

  condition:
    any of them
}