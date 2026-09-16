rule TTP_XOR_MULT_DOSStub_e8d5 {
  strings:
    $key_e8d5 = { bc bd [2] c8 a5 [2] 8f a7 [2] c8 b6 [2] 86 ba [2] 8a b0 [2] 9d bb [2] 86 f5 [2] bb }

  condition:
    any of them
}