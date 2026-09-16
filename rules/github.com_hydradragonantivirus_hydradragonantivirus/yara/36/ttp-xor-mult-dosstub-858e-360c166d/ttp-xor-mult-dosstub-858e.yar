rule TTP_XOR_MULT_DOSStub_858e {
  strings:
    $key_858e = { d1 e6 [2] a5 fe [2] e2 fc [2] a5 ed [2] eb e1 [2] e7 eb [2] f0 e0 [2] eb ae [2] d6 }

  condition:
    any of them
}