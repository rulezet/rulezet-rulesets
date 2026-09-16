rule TTP_XOR_MULT_DOSStub_878e {
  strings:
    $key_878e = { d3 e6 [2] a7 fe [2] e0 fc [2] a7 ed [2] e9 e1 [2] e5 eb [2] f2 e0 [2] e9 ae [2] d4 }

  condition:
    any of them
}