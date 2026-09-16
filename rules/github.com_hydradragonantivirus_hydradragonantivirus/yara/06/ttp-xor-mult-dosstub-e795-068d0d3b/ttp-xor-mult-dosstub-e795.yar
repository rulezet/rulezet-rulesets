rule TTP_XOR_MULT_DOSStub_e795 {
  strings:
    $key_e795 = { b3 fd [2] c7 e5 [2] 80 e7 [2] c7 f6 [2] 89 fa [2] 85 f0 [2] 92 fb [2] 89 b5 [2] b4 }

  condition:
    any of them
}