rule TTP_XOR_MULT_DOSStub_8f20 {
  strings:
    $key_8f20 = { db 48 [2] af 50 [2] e8 52 [2] af 43 [2] e1 4f [2] ed 45 [2] fa 4e [2] e1 00 [2] dc }

  condition:
    any of them
}