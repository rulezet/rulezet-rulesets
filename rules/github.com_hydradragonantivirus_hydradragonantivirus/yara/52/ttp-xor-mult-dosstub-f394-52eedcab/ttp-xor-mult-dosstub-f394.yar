rule TTP_XOR_MULT_DOSStub_f394 {
  strings:
    $key_f394 = { a7 fc [2] d3 e4 [2] 94 e6 [2] d3 f7 [2] 9d fb [2] 91 f1 [2] 86 fa [2] 9d b4 [2] a0 }

  condition:
    any of them
}