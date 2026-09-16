rule TTP_XOR_MULT_DOSStub_8f97 {
  strings:
    $key_8f97 = { db ff [2] af e7 [2] e8 e5 [2] af f4 [2] e1 f8 [2] ed f2 [2] fa f9 [2] e1 b7 [2] dc }

  condition:
    any of them
}