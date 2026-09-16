rule TTP_XOR_MULT_DOSStub_8f95 {
  strings:
    $key_8f95 = { db fd [2] af e5 [2] e8 e7 [2] af f6 [2] e1 fa [2] ed f0 [2] fa fb [2] e1 b5 [2] dc }

  condition:
    any of them
}