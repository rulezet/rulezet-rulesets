rule TTP_XOR_MULT_DOSStub_8f92 {
  strings:
    $key_8f92 = { db fa [2] af e2 [2] e8 e0 [2] af f1 [2] e1 fd [2] ed f7 [2] fa fc [2] e1 b2 [2] dc }

  condition:
    any of them
}