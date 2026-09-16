rule TTP_XOR_MULT_DOSStub_0ad4 {
  strings:
    $key_0ad4 = { 5e bc [2] 2a a4 [2] 6d a6 [2] 2a b7 [2] 64 bb [2] 68 b1 [2] 7f ba [2] 64 f4 [2] 59 }

  condition:
    any of them
}