rule TTP_XOR_MULT_DOSStub_e78b {
  strings:
    $key_e78b = { b3 e3 [2] c7 fb [2] 80 f9 [2] c7 e8 [2] 89 e4 [2] 85 ee [2] 92 e5 [2] 89 ab [2] b4 }

  condition:
    any of them
}