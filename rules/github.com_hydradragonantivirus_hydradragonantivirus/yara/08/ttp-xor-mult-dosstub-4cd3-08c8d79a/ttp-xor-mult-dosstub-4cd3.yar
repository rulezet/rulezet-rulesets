rule TTP_XOR_MULT_DOSStub_4cd3 {
  strings:
    $key_4cd3 = { 18 bb [2] 6c a3 [2] 2b a1 [2] 6c b0 [2] 22 bc [2] 2e b6 [2] 39 bd [2] 22 f3 [2] 1f }

  condition:
    any of them
}