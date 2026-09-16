rule TTP_XOR_MULT_DOSStub_f192 {
  strings:
    $key_f192 = { a5 fa [2] d1 e2 [2] 96 e0 [2] d1 f1 [2] 9f fd [2] 93 f7 [2] 84 fc [2] 9f b2 [2] a2 }

  condition:
    any of them
}