rule TTP_XOR_MULT_DOSStub_7dd4 {
  strings:
    $key_7dd4 = { 29 bc [2] 5d a4 [2] 1a a6 [2] 5d b7 [2] 13 bb [2] 1f b1 [2] 08 ba [2] 13 f4 [2] 2e }

  condition:
    any of them
}