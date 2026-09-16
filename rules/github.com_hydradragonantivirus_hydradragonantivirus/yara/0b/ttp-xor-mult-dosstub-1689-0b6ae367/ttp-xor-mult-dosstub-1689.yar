rule TTP_XOR_MULT_DOSStub_1689 {
  strings:
    $key_1689 = { 42 e1 [2] 36 f9 [2] 71 fb [2] 36 ea [2] 78 e6 [2] 74 ec [2] 63 e7 [2] 78 a9 [2] 45 }

  condition:
    any of them
}