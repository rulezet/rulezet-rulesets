rule TTP_XOR_MULT_DOSStub_968e {
  strings:
    $key_968e = { c2 e6 [2] b6 fe [2] f1 fc [2] b6 ed [2] f8 e1 [2] f4 eb [2] e3 e0 [2] f8 ae [2] c5 }

  condition:
    any of them
}