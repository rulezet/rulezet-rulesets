rule TTP_XOR_MULT_DOSStub_918e {
  strings:
    $key_918e = { c5 e6 [2] b1 fe [2] f6 fc [2] b1 ed [2] ff e1 [2] f3 eb [2] e4 e0 [2] ff ae [2] c2 }

  condition:
    any of them
}