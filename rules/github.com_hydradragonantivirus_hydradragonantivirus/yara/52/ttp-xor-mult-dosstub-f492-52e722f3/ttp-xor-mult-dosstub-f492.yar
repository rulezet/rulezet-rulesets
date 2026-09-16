rule TTP_XOR_MULT_DOSStub_f492 {
  strings:
    $key_f492 = { a0 fa [2] d4 e2 [2] 93 e0 [2] d4 f1 [2] 9a fd [2] 96 f7 [2] 81 fc [2] 9a b2 [2] a7 }

  condition:
    any of them
}