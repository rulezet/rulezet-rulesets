rule TTP_XOR_MULT_DOSStub_08d3 {
  strings:
    $key_08d3 = { 5c bb [2] 28 a3 [2] 6f a1 [2] 28 b0 [2] 66 bc [2] 6a b6 [2] 7d bd [2] 66 f3 [2] 5b }

  condition:
    any of them
}