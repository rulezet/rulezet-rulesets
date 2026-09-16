rule TTP_XOR_MULT_DOSStub_28d3 {
  strings:
    $key_28d3 = { 7c bb [2] 08 a3 [2] 4f a1 [2] 08 b0 [2] 46 bc [2] 4a b6 [2] 5d bd [2] 46 f3 [2] 7b }

  condition:
    any of them
}