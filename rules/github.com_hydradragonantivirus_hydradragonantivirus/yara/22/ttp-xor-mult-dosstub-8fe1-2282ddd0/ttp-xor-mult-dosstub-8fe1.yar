rule TTP_XOR_MULT_DOSStub_8fe1 {
  strings:
    $key_8fe1 = { db 89 [2] af 91 [2] e8 93 [2] af 82 [2] e1 8e [2] ed 84 [2] fa 8f [2] e1 c1 [2] dc }

  condition:
    any of them
}