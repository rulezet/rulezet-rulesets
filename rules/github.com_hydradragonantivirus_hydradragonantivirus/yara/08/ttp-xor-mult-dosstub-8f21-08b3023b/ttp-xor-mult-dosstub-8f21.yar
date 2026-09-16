rule TTP_XOR_MULT_DOSStub_8f21 {
  strings:
    $key_8f21 = { db 49 [2] af 51 [2] e8 53 [2] af 42 [2] e1 4e [2] ed 44 [2] fa 4f [2] e1 01 [2] dc }

  condition:
    any of them
}