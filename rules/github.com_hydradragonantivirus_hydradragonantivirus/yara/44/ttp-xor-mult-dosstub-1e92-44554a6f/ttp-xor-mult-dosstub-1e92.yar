rule TTP_XOR_MULT_DOSStub_1e92 {
  strings:
    $key_1e92 = { 4a fa [2] 3e e2 [2] 79 e0 [2] 3e f1 [2] 70 fd [2] 7c f7 [2] 6b fc [2] 70 b2 [2] 4d }

  condition:
    any of them
}