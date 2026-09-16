rule TTP_XOR_MULT_DOSStub_808e {
  strings:
    $key_808e = { d4 e6 [2] a0 fe [2] e7 fc [2] a0 ed [2] ee e1 [2] e2 eb [2] f5 e0 [2] ee ae [2] d3 }

  condition:
    any of them
}