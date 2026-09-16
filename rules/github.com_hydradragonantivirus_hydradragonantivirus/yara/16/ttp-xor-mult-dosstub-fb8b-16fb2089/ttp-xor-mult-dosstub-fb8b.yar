rule TTP_XOR_MULT_DOSStub_fb8b {
  strings:
    $key_fb8b = { af e3 [2] db fb [2] 9c f9 [2] db e8 [2] 95 e4 [2] 99 ee [2] 8e e5 [2] 95 ab [2] a8 }

  condition:
    any of them
}