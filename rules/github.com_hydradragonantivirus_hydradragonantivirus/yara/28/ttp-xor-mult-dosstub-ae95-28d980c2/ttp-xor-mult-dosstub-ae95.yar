rule TTP_XOR_MULT_DOSStub_ae95 {
  strings:
    $key_ae95 = { fa fd [2] 8e e5 [2] c9 e7 [2] 8e f6 [2] c0 fa [2] cc f0 [2] db fb [2] c0 b5 [2] fd }

  condition:
    any of them
}