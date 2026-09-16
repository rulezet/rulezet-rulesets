rule TTP_XOR_MULT_DOSStub_a88b {
  strings:
    $key_a88b = { fc e3 [2] 88 fb [2] cf f9 [2] 88 e8 [2] c6 e4 [2] ca ee [2] dd e5 [2] c6 ab [2] fb }

  condition:
    any of them
}