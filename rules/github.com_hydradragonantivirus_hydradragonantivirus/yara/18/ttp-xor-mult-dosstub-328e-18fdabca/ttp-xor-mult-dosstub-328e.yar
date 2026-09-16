rule TTP_XOR_MULT_DOSStub_328e {
  strings:
    $key_328e = { 66 e6 [2] 12 fe [2] 55 fc [2] 12 ed [2] 5c e1 [2] 50 eb [2] 47 e0 [2] 5c ae [2] 61 }

  condition:
    any of them
}