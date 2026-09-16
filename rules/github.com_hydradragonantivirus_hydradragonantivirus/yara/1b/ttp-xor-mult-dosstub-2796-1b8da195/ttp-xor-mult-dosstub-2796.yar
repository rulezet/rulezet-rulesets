rule TTP_XOR_MULT_DOSStub_2796 {
  strings:
    $key_2796 = { 73 fe [2] 07 e6 [2] 40 e4 [2] 07 f5 [2] 49 f9 [2] 45 f3 [2] 52 f8 [2] 49 b6 [2] 74 }

  condition:
    any of them
}