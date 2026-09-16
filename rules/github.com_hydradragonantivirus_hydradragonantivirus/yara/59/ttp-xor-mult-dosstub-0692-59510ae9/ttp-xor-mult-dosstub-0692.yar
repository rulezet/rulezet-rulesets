rule TTP_XOR_MULT_DOSStub_0692 {
  strings:
    $key_0692 = { 52 fa [2] 26 e2 [2] 61 e0 [2] 26 f1 [2] 68 fd [2] 64 f7 [2] 73 fc [2] 68 b2 [2] 55 }

  condition:
    any of them
}