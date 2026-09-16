rule TTP_XOR_MULT_DOSStub_b98b {
  strings:
    $key_b98b = { ed e3 [2] 99 fb [2] de f9 [2] 99 e8 [2] d7 e4 [2] db ee [2] cc e5 [2] d7 ab [2] ea }

  condition:
    any of them
}