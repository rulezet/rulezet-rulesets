rule TTP_XOR_MULT_DOSStub_598e {
  strings:
    $key_598e = { 0d e6 [2] 79 fe [2] 3e fc [2] 79 ed [2] 37 e1 [2] 3b eb [2] 2c e0 [2] 37 ae [2] 0a }

  condition:
    any of them
}