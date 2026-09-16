rule TTP_XOR_MULT_DOSStub_978e {
  strings:
    $key_978e = { c3 e6 [2] b7 fe [2] f0 fc [2] b7 ed [2] f9 e1 [2] f5 eb [2] e2 e0 [2] f9 ae [2] c4 }

  condition:
    any of them
}