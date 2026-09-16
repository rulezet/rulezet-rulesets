rule TTP_XOR_MULT_DOSStub_78d3 {
  strings:
    $key_78d3 = { 2c bb [2] 58 a3 [2] 1f a1 [2] 58 b0 [2] 16 bc [2] 1a b6 [2] 0d bd [2] 16 f3 [2] 2b }

  condition:
    any of them
}