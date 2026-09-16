rule TTP_XOR_MULT_DOSStub_2696 {
  strings:
    $key_2696 = { 72 fe [2] 06 e6 [2] 41 e4 [2] 06 f5 [2] 48 f9 [2] 44 f3 [2] 53 f8 [2] 48 b6 [2] 75 }

  condition:
    any of them
}