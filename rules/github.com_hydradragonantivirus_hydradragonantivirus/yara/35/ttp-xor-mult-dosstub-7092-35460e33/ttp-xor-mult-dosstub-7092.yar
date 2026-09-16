rule TTP_XOR_MULT_DOSStub_7092 {
  strings:
    $key_7092 = { 24 fa [2] 50 e2 [2] 17 e0 [2] 50 f1 [2] 1e fd [2] 12 f7 [2] 05 fc [2] 1e b2 [2] 23 }

  condition:
    any of them
}