rule TTP_XOR_MULT_DOSStub_e689 {
  strings:
    $key_e689 = { b2 e1 [2] c6 f9 [2] 81 fb [2] c6 ea [2] 88 e6 [2] 84 ec [2] 93 e7 [2] 88 a9 [2] b5 }

  condition:
    any of them
}