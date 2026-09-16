rule TTP_XOR_MULT_DOSStub_b792 {
  strings:
    $key_b792 = { e3 fa [2] 97 e2 [2] d0 e0 [2] 97 f1 [2] d9 fd [2] d5 f7 [2] c2 fc [2] d9 b2 [2] e4 }

  condition:
    any of them
}