rule TTP_XOR_MULT_DOSStub_ec8d {
  strings:
    $key_ec8d = { b8 e5 [2] cc fd [2] 8b ff [2] cc ee [2] 82 e2 [2] 8e e8 [2] 99 e3 [2] 82 ad [2] bf }

  condition:
    any of them
}