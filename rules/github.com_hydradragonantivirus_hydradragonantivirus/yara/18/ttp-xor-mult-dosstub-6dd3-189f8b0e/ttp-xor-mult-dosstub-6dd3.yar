rule TTP_XOR_MULT_DOSStub_6dd3 {
  strings:
    $key_6dd3 = { 39 bb [2] 4d a3 [2] 0a a1 [2] 4d b0 [2] 03 bc [2] 0f b6 [2] 18 bd [2] 03 f3 [2] 3e }

  condition:
    any of them
}