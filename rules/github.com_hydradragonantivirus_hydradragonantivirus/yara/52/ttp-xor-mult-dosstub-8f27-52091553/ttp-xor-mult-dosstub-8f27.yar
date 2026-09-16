rule TTP_XOR_MULT_DOSStub_8f27 {
  strings:
    $key_8f27 = { db 4f [2] af 57 [2] e8 55 [2] af 44 [2] e1 48 [2] ed 42 [2] fa 49 [2] e1 07 [2] dc }

  condition:
    any of them
}