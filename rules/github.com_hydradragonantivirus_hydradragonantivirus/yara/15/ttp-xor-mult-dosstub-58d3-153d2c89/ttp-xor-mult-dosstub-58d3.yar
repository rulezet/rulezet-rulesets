rule TTP_XOR_MULT_DOSStub_58d3 {
  strings:
    $key_58d3 = { 0c bb [2] 78 a3 [2] 3f a1 [2] 78 b0 [2] 36 bc [2] 3a b6 [2] 2d bd [2] 36 f3 [2] 0b }

  condition:
    any of them
}