rule TTP_XOR_MULT_DOSStub_2e92 {
  strings:
    $key_2e92 = { 7a fa [2] 0e e2 [2] 49 e0 [2] 0e f1 [2] 40 fd [2] 4c f7 [2] 5b fc [2] 40 b2 [2] 7d }

  condition:
    any of them
}