rule TTP_XOR_MULT_DOSStub_ec8e {
  strings:
    $key_ec8e = { b8 e6 [2] cc fe [2] 8b fc [2] cc ed [2] 82 e1 [2] 8e eb [2] 99 e0 [2] 82 ae [2] bf }

  condition:
    any of them
}