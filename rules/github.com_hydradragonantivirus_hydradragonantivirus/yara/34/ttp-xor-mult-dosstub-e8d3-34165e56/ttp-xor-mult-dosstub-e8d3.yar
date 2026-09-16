rule TTP_XOR_MULT_DOSStub_e8d3 {
  strings:
    $key_e8d3 = { bc bb [2] c8 a3 [2] 8f a1 [2] c8 b0 [2] 86 bc [2] 8a b6 [2] 9d bd [2] 86 f3 [2] bb }

  condition:
    any of them
}