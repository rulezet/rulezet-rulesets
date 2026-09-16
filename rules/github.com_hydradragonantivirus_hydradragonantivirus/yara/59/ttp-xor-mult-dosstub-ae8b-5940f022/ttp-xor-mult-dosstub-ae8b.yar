rule TTP_XOR_MULT_DOSStub_ae8b {
  strings:
    $key_ae8b = { fa e3 [2] 8e fb [2] c9 f9 [2] 8e e8 [2] c0 e4 [2] cc ee [2] db e5 [2] c0 ab [2] fd }

  condition:
    any of them
}