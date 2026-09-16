rule TTP_XOR_MULT_DOSStub_8a8b {
  strings:
    $key_8a8b = { de e3 [2] aa fb [2] ed f9 [2] aa e8 [2] e4 e4 [2] e8 ee [2] ff e5 [2] e4 ab [2] d9 }

  condition:
    any of them
}