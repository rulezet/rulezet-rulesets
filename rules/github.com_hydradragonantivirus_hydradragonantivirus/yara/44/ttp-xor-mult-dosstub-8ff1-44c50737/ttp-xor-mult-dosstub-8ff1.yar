rule TTP_XOR_MULT_DOSStub_8ff1 {
  strings:
    $key_8ff1 = { db 99 [2] af 81 [2] e8 83 [2] af 92 [2] e1 9e [2] ed 94 [2] fa 9f [2] e1 d1 [2] dc }

  condition:
    any of them
}