rule TTP_XOR_MULT_DOSStub_0f9e {
  strings:
    $key_0f9e = { 5b f6 [2] 2f ee [2] 68 ec [2] 2f fd [2] 61 f1 [2] 6d fb [2] 7a f0 [2] 61 be [2] 5c }

  condition:
    any of them
}