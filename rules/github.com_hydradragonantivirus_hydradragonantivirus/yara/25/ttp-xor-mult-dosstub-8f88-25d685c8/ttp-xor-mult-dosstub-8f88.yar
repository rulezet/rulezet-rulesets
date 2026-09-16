rule TTP_XOR_MULT_DOSStub_8f88 {
  strings:
    $key_8f88 = { db e0 [2] af f8 [2] e8 fa [2] af eb [2] e1 e7 [2] ed ed [2] fa e6 [2] e1 a8 [2] dc }

  condition:
    any of them
}