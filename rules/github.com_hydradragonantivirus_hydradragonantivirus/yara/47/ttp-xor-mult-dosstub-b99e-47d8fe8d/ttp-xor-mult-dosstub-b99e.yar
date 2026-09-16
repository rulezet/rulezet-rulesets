rule TTP_XOR_MULT_DOSStub_b99e {
  strings:
    $key_b99e = { ed f6 [2] 99 ee [2] de ec [2] 99 fd [2] d7 f1 [2] db fb [2] cc f0 [2] d7 be [2] ea }

  condition:
    any of them
}