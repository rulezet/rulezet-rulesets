rule TTP_XOR_MULT_DOSStub_18d4 {
  strings:
    $key_18d4 = { 4c bc [2] 38 a4 [2] 7f a6 [2] 38 b7 [2] 76 bb [2] 7a b1 [2] 6d ba [2] 76 f4 [2] 4b }

  condition:
    any of them
}