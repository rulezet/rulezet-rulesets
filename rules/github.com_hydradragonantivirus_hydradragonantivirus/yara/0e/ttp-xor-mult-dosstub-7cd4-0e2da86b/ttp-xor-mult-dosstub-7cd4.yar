rule TTP_XOR_MULT_DOSStub_7cd4 {
  strings:
    $key_7cd4 = { 28 bc [2] 5c a4 [2] 1b a6 [2] 5c b7 [2] 12 bb [2] 1e b1 [2] 09 ba [2] 12 f4 [2] 2f }

  condition:
    any of them
}