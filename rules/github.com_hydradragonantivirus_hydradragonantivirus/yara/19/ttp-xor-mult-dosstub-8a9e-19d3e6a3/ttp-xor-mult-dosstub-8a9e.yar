rule TTP_XOR_MULT_DOSStub_8a9e {
  strings:
    $key_8a9e = { de f6 [2] aa ee [2] ed ec [2] aa fd [2] e4 f1 [2] e8 fb [2] ff f0 [2] e4 be [2] d9 }

  condition:
    any of them
}