rule TTP_XOR_MULT_DOSStub_b78b {
  strings:
    $key_b78b = { e3 e3 [2] 97 fb [2] d0 f9 [2] 97 e8 [2] d9 e4 [2] d5 ee [2] c2 e5 [2] d9 ab [2] e4 }

  condition:
    any of them
}