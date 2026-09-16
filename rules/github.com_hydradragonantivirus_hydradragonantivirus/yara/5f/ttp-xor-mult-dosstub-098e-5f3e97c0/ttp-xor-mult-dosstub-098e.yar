rule TTP_XOR_MULT_DOSStub_098e {
  strings:
    $key_098e = { 5d e6 [2] 29 fe [2] 6e fc [2] 29 ed [2] 67 e1 [2] 6b eb [2] 7c e0 [2] 67 ae [2] 5a }

  condition:
    any of them
}