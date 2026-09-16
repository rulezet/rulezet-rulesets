rule TTP_XOR_MULT_DOSStub_b38e {
  strings:
    $key_b38e = { e7 e6 [2] 93 fe [2] d4 fc [2] 93 ed [2] dd e1 [2] d1 eb [2] c6 e0 [2] dd ae [2] e0 }

  condition:
    any of them
}