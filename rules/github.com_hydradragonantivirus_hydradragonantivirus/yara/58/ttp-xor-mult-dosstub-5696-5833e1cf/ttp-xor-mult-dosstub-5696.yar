rule TTP_XOR_MULT_DOSStub_5696 {
  strings:
    $key_5696 = { 02 fe [2] 76 e6 [2] 31 e4 [2] 76 f5 [2] 38 f9 [2] 34 f3 [2] 23 f8 [2] 38 b6 [2] 05 }

  condition:
    any of them
}