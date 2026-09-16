rule TTP_XOR_MULT_DOSStub_ec9e {
  strings:
    $key_ec9e = { b8 f6 [2] cc ee [2] 8b ec [2] cc fd [2] 82 f1 [2] 8e fb [2] 99 f0 [2] 82 be [2] bf }

  condition:
    any of them
}