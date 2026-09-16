rule TTP_XOR_MULT_DOSStub_7796 {
  strings:
    $key_7796 = { 23 fe [2] 57 e6 [2] 10 e4 [2] 57 f5 [2] 19 f9 [2] 15 f3 [2] 02 f8 [2] 19 b6 [2] 24 }

  condition:
    any of them
}