rule TTP_XOR_MULT_DOSStub_188e {
  strings:
    $key_188e = { 4c e6 [2] 38 fe [2] 7f fc [2] 38 ed [2] 76 e1 [2] 7a eb [2] 6d e0 [2] 76 ae [2] 4b }

  condition:
    any of them
}