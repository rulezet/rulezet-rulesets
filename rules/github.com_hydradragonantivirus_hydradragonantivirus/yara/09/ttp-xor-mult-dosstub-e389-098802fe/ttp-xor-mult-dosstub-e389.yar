rule TTP_XOR_MULT_DOSStub_e389 {
  strings:
    $key_e389 = { b7 e1 [2] c3 f9 [2] 84 fb [2] c3 ea [2] 8d e6 [2] 81 ec [2] 96 e7 [2] 8d a9 [2] b0 }

  condition:
    any of them
}