rule TTP_XOR_MULT_DOSStub_b58e {
  strings:
    $key_b58e = { e1 e6 [2] 95 fe [2] d2 fc [2] 95 ed [2] db e1 [2] d7 eb [2] c0 e0 [2] db ae [2] e6 }

  condition:
    any of them
}