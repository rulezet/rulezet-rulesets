rule TTP_XOR_MULT_DOSStub_3e92 {
  strings:
    $key_3e92 = { 6a fa [2] 1e e2 [2] 59 e0 [2] 1e f1 [2] 50 fd [2] 5c f7 [2] 4b fc [2] 50 b2 [2] 6d }

  condition:
    any of them
}