rule TTP_XOR_MULT_DOSStub_688e {
  strings:
    $key_688e = { 3c e6 [2] 48 fe [2] 0f fc [2] 48 ed [2] 06 e1 [2] 0a eb [2] 1d e0 [2] 06 ae [2] 3b }

  condition:
    any of them
}