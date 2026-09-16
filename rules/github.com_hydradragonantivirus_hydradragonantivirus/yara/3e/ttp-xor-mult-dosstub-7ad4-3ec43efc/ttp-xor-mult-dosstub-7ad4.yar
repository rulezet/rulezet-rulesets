rule TTP_XOR_MULT_DOSStub_7ad4 {
  strings:
    $key_7ad4 = { 2e bc [2] 5a a4 [2] 1d a6 [2] 5a b7 [2] 14 bb [2] 18 b1 [2] 0f ba [2] 14 f4 [2] 29 }

  condition:
    any of them
}