rule TTP_XOR_MULT_DOSStub_4492 {
  strings:
    $key_4492 = { 10 fa [2] 64 e2 [2] 23 e0 [2] 64 f1 [2] 2a fd [2] 26 f7 [2] 31 fc [2] 2a b2 [2] 17 }

  condition:
    any of them
}