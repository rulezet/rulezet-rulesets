rule TTP_XOR_MULT_DOSStub_8f8e {
  strings:
    $key_8f8e = { db e6 [2] af fe [2] e8 fc [2] af ed [2] e1 e1 [2] ed eb [2] fa e0 [2] e1 ae [2] dc }

  condition:
    any of them
}