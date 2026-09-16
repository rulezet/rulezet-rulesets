rule TTP_XOR_MULT_DOSStub_838e {
  strings:
    $key_838e = { d7 e6 [2] a3 fe [2] e4 fc [2] a3 ed [2] ed e1 [2] e1 eb [2] f6 e0 [2] ed ae [2] d0 }

  condition:
    any of them
}