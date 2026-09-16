rule TTP_XOR_MULT_DOSStub_ab8e {
  strings:
    $key_ab8e = { ff e6 [2] 8b fe [2] cc fc [2] 8b ed [2] c5 e1 [2] c9 eb [2] de e0 [2] c5 ae [2] f8 }

  condition:
    any of them
}