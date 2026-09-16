rule TTP_XOR_MULT_DOSStub_8f26 {
  strings:
    $key_8f26 = { db 4e [2] af 56 [2] e8 54 [2] af 45 [2] e1 49 [2] ed 43 [2] fa 48 [2] e1 06 [2] dc }

  condition:
    any of them
}