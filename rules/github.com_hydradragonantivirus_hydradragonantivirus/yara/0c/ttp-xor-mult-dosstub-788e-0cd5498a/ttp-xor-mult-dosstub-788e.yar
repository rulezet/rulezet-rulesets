rule TTP_XOR_MULT_DOSStub_788e {
  strings:
    $key_788e = { 2c e6 [2] 58 fe [2] 1f fc [2] 58 ed [2] 16 e1 [2] 1a eb [2] 0d e0 [2] 16 ae [2] 2b }

  condition:
    any of them
}