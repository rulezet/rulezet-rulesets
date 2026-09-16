rule TTP_XOR_MULT_DOSStub_818e {
  strings:
    $key_818e = { d5 e6 [2] a1 fe [2] e6 fc [2] a1 ed [2] ef e1 [2] e3 eb [2] f4 e0 [2] ef ae [2] d2 }

  condition:
    any of them
}