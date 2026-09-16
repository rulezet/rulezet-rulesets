rule TTP_XOR_MULT_DOSStub_f795 {
  strings:
    $key_f795 = { a3 fd [2] d7 e5 [2] 90 e7 [2] d7 f6 [2] 99 fa [2] 95 f0 [2] 82 fb [2] 99 b5 [2] a4 }

  condition:
    any of them
}