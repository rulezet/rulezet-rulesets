rule TTP_XOR_MULT_DOSStub_8a98 {
  strings:
    $key_8a98 = { de f0 [2] aa e8 [2] ed ea [2] aa fb [2] e4 f7 [2] e8 fd [2] ff f6 [2] e4 b8 [2] d9 }

  condition:
    any of them
}