rule TTP_XOR_MULT_DOSStub_848e {
  strings:
    $key_848e = { d0 e6 [2] a4 fe [2] e3 fc [2] a4 ed [2] ea e1 [2] e6 eb [2] f1 e0 [2] ea ae [2] d7 }

  condition:
    any of them
}