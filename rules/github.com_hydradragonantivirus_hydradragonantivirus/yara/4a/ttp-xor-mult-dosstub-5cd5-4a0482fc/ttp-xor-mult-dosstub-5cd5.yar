rule TTP_XOR_MULT_DOSStub_5cd5 {
  strings:
    $key_5cd5 = { 08 bd [2] 7c a5 [2] 3b a7 [2] 7c b6 [2] 32 ba [2] 3e b0 [2] 29 bb [2] 32 f5 [2] 0f }

  condition:
    any of them
}