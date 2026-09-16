rule TTP_XOR_MULT_DOSStub_898b {
  strings:
    $key_898b = { dd e3 [2] a9 fb [2] ee f9 [2] a9 e8 [2] e7 e4 [2] eb ee [2] fc e5 [2] e7 ab [2] da }

  condition:
    any of them
}