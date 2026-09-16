rule TTP_XOR_MULT_DOSStub_928e {
  strings:
    $key_928e = { c6 e6 [2] b2 fe [2] f5 fc [2] b2 ed [2] fc e1 [2] f0 eb [2] e7 e0 [2] fc ae [2] c1 }

  condition:
    any of them
}