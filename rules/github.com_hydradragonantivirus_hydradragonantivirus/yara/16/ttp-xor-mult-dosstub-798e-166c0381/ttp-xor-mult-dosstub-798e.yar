rule TTP_XOR_MULT_DOSStub_798e {
  strings:
    $key_798e = { 2d e6 [2] 59 fe [2] 1e fc [2] 59 ed [2] 17 e1 [2] 1b eb [2] 0c e0 [2] 17 ae [2] 2a }

  condition:
    any of them
}