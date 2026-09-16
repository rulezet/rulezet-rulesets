rule TTP_XOR_MULT_DOSStub_828e {
  strings:
    $key_828e = { d6 e6 [2] a2 fe [2] e5 fc [2] a2 ed [2] ec e1 [2] e0 eb [2] f7 e0 [2] ec ae [2] d1 }

  condition:
    any of them
}