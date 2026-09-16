rule TTP_XOR_MULT_DOSStub_1796 {
  strings:
    $key_1796 = { 43 fe [2] 37 e6 [2] 70 e4 [2] 37 f5 [2] 79 f9 [2] 75 f3 [2] 62 f8 [2] 79 b6 [2] 44 }

  condition:
    any of them
}