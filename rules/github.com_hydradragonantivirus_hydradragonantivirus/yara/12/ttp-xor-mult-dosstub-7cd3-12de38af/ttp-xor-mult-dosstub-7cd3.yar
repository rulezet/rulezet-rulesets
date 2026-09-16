rule TTP_XOR_MULT_DOSStub_7cd3 {
  strings:
    $key_7cd3 = { 28 bb [2] 5c a3 [2] 1b a1 [2] 5c b0 [2] 12 bc [2] 1e b6 [2] 09 bd [2] 12 f3 [2] 2f }

  condition:
    any of them
}