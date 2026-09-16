rule TTP_XOR_MULT_DOSStub_38d4 {
  strings:
    $key_38d4 = { 6c bc [2] 18 a4 [2] 5f a6 [2] 18 b7 [2] 56 bb [2] 5a b1 [2] 4d ba [2] 56 f4 [2] 6b }

  condition:
    any of them
}