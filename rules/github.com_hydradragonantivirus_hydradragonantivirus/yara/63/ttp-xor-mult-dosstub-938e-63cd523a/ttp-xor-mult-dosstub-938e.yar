rule TTP_XOR_MULT_DOSStub_938e {
  strings:
    $key_938e = { c7 e6 [2] b3 fe [2] f4 fc [2] b3 ed [2] fd e1 [2] f1 eb [2] e6 e0 [2] fd ae [2] c0 }

  condition:
    any of them
}