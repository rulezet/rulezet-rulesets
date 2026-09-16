rule TTP_XOR_MULT_DOSStub_b795 {
  strings:
    $key_b795 = { e3 fd [2] 97 e5 [2] d0 e7 [2] 97 f6 [2] d9 fa [2] d5 f0 [2] c2 fb [2] d9 b5 [2] e4 }

  condition:
    any of them
}