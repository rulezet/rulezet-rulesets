rule TTP_XOR_MULT_DOSStub_8f30 {
  strings:
    $key_8f30 = { db 58 [2] af 40 [2] e8 42 [2] af 53 [2] e1 5f [2] ed 55 [2] fa 5e [2] e1 10 [2] dc }

  condition:
    any of them
}