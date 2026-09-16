rule TTP_XOR_MULT_DOSStub_e495 {
  strings:
    $key_e495 = { b0 fd [2] c4 e5 [2] 83 e7 [2] c4 f6 [2] 8a fa [2] 86 f0 [2] 91 fb [2] 8a b5 [2] b7 }

  condition:
    any of them
}