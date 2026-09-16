rule TTP_XOR_MULT_DOSStub_b394 {
  strings:
    $key_b394 = { e7 fc [2] 93 e4 [2] d4 e6 [2] 93 f7 [2] dd fb [2] d1 f1 [2] c6 fa [2] dd b4 [2] e0 }

  condition:
    any of them
}