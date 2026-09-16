rule TTP_XOR_MULT_DOSStub_e692 {
  strings:
    $key_e692 = { b2 fa [2] c6 e2 [2] 81 e0 [2] c6 f1 [2] 88 fd [2] 84 f7 [2] 93 fc [2] 88 b2 [2] b5 }

  condition:
    any of them
}