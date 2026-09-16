rule TTP_XOR_MULT_DOSStub_0c8e {
  strings:
    $key_0c8e = { 58 e6 [2] 2c fe [2] 6b fc [2] 2c ed [2] 62 e1 [2] 6e eb [2] 79 e0 [2] 62 ae [2] 5f }

  condition:
    any of them
}