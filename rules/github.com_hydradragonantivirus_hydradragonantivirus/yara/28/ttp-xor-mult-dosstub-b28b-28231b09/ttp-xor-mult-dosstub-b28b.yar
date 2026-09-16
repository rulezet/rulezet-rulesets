rule TTP_XOR_MULT_DOSStub_b28b {
  strings:
    $key_b28b = { e6 e3 [2] 92 fb [2] d5 f9 [2] 92 e8 [2] dc e4 [2] d0 ee [2] c7 e5 [2] dc ab [2] e1 }

  condition:
    any of them
}