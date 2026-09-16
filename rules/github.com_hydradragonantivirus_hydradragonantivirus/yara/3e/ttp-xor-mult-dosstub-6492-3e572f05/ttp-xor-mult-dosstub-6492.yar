rule TTP_XOR_MULT_DOSStub_6492 {
  strings:
    $key_6492 = { 30 fa [2] 44 e2 [2] 03 e0 [2] 44 f1 [2] 0a fd [2] 06 f7 [2] 11 fc [2] 0a b2 [2] 37 }

  condition:
    any of them
}