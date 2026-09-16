rule TTP_XOR_MULT_DOSStub_2798 {
  strings:
    $key_2798 = { 73 f0 [2] 07 e8 [2] 40 ea [2] 07 fb [2] 49 f7 [2] 45 fd [2] 52 f6 [2] 49 b8 [2] 74 }

  condition:
    any of them
}