rule TTP_XOR_MULT_DOSStub_f792 {
  strings:
    $key_f792 = { a3 fa [2] d7 e2 [2] 90 e0 [2] d7 f1 [2] 99 fd [2] 95 f7 [2] 82 fc [2] 99 b2 [2] a4 }

  condition:
    any of them
}