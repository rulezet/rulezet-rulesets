rule TTP_XOR_MULT_DOSStub_e08b {
  strings:
    $key_e08b = { b4 e3 [2] c0 fb [2] 87 f9 [2] c0 e8 [2] 8e e4 [2] 82 ee [2] 95 e5 [2] 8e ab [2] b3 }

  condition:
    any of them
}