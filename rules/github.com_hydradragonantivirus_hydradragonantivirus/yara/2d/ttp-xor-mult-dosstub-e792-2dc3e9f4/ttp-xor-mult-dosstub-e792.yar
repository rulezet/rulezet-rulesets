rule TTP_XOR_MULT_DOSStub_e792 {
  strings:
    $key_e792 = { b3 fa [2] c7 e2 [2] 80 e0 [2] c7 f1 [2] 89 fd [2] 85 f7 [2] 92 fc [2] 89 b2 [2] b4 }

  condition:
    any of them
}