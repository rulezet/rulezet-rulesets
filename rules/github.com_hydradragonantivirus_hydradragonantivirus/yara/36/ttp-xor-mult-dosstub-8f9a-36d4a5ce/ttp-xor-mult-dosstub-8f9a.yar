rule TTP_XOR_MULT_DOSStub_8f9a {
  strings:
    $key_8f9a = { db f2 [2] af ea [2] e8 e8 [2] af f9 [2] e1 f5 [2] ed ff [2] fa f4 [2] e1 ba [2] dc }

  condition:
    any of them
}