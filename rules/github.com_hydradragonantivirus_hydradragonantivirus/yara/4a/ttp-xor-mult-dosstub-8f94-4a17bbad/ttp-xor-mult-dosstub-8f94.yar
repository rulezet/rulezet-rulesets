rule TTP_XOR_MULT_DOSStub_8f94 {
  strings:
    $key_8f94 = { db fc [2] af e4 [2] e8 e6 [2] af f7 [2] e1 fb [2] ed f1 [2] fa fa [2] e1 b4 [2] dc }

  condition:
    any of them
}