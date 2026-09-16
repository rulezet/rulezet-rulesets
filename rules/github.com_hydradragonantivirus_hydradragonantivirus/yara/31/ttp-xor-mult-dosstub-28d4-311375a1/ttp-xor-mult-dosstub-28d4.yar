rule TTP_XOR_MULT_DOSStub_28d4 {
  strings:
    $key_28d4 = { 7c bc [2] 08 a4 [2] 4f a6 [2] 08 b7 [2] 46 bb [2] 4a b1 [2] 5d ba [2] 46 f4 [2] 7b }

  condition:
    any of them
}