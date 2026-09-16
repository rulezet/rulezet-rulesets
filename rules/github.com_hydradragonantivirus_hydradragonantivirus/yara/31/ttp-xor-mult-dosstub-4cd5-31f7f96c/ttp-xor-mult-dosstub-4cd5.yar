rule TTP_XOR_MULT_DOSStub_4cd5 {
  strings:
    $key_4cd5 = { 18 bd [2] 6c a5 [2] 2b a7 [2] 6c b6 [2] 22 ba [2] 2e b0 [2] 39 bb [2] 22 f5 [2] 1f }

  condition:
    any of them
}