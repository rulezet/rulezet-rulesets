rule TTP_XOR_MULT_DOSStub_f28e {
  strings:
    $key_f28e = { a6 e6 [2] d2 fe [2] 95 fc [2] d2 ed [2] 9c e1 [2] 90 eb [2] 87 e0 [2] 9c ae [2] a1 }

  condition:
    any of them
}