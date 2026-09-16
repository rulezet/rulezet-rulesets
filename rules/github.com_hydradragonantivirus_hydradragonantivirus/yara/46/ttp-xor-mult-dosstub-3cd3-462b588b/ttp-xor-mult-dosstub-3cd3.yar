rule TTP_XOR_MULT_DOSStub_3cd3 {
  strings:
    $key_3cd3 = { 68 bb [2] 1c a3 [2] 5b a1 [2] 1c b0 [2] 52 bc [2] 5e b6 [2] 49 bd [2] 52 f3 [2] 6f }

  condition:
    any of them
}