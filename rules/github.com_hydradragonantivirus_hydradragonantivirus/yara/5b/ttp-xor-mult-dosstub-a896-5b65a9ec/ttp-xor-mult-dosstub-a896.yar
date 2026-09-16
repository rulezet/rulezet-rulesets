rule TTP_XOR_MULT_DOSStub_a896 {
  strings:
    $key_a896 = { fc fe [2] 88 e6 [2] cf e4 [2] 88 f5 [2] c6 f9 [2] ca f3 [2] dd f8 [2] c6 b6 [2] fb }

  condition:
    any of them
}