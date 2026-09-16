rule TTP_XOR_MULT_DOSStub_1184 {
  strings:
    $key_1184 = { 45 ec [2] 31 f4 [2] 76 f6 [2] 31 e7 [2] 7f eb [2] 73 e1 [2] 64 ea [2] 7f a4 [2] 42 }

  condition:
    any of them
}