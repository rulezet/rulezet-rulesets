rule TTP_XOR_MULT_DOSStub_178e {
  strings:
    $key_178e = { 43 e6 [2] 37 fe [2] 70 fc [2] 37 ed [2] 79 e1 [2] 75 eb [2] 62 e0 [2] 79 ae [2] 44 }

  condition:
    any of them
}