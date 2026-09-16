rule TTP_XOR_MULT_DOSStub_e392 {
  strings:
    $key_e392 = { b7 fa [2] c3 e2 [2] 84 e0 [2] c3 f1 [2] 8d fd [2] 81 f7 [2] 96 fc [2] 8d b2 [2] b0 }

  condition:
    any of them
}