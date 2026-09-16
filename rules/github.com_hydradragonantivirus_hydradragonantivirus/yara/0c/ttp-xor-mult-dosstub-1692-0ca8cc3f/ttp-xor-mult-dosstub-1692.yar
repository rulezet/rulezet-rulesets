rule TTP_XOR_MULT_DOSStub_1692 {
  strings:
    $key_1692 = { 42 fa [2] 36 e2 [2] 71 e0 [2] 36 f1 [2] 78 fd [2] 74 f7 [2] 63 fc [2] 78 b2 [2] 45 }

  condition:
    any of them
}