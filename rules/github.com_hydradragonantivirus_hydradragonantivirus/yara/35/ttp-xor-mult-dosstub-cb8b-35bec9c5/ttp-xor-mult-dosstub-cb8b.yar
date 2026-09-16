rule TTP_XOR_MULT_DOSStub_cb8b {
  strings:
    $key_cb8b = { 9f e3 [2] eb fb [2] ac f9 [2] eb e8 [2] a5 e4 [2] a9 ee [2] be e5 [2] a5 ab [2] 98 }

  condition:
    any of them
}