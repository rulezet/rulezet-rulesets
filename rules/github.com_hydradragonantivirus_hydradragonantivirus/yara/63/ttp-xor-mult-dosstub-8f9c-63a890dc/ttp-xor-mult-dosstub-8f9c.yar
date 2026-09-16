rule TTP_XOR_MULT_DOSStub_8f9c {
  strings:
    $key_8f9c = { db f4 [2] af ec [2] e8 ee [2] af ff [2] e1 f3 [2] ed f9 [2] fa f2 [2] e1 bc [2] dc }

  condition:
    any of them
}