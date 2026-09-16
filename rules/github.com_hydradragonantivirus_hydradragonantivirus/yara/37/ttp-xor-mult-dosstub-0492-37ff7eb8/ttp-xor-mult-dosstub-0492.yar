rule TTP_XOR_MULT_DOSStub_0492 {
  strings:
    $key_0492 = { 50 fa [2] 24 e2 [2] 63 e0 [2] 24 f1 [2] 6a fd [2] 66 f7 [2] 71 fc [2] 6a b2 [2] 57 }

  condition:
    any of them
}