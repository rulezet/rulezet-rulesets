rule TTP_XOR_MULT_DOSStub_8f50 {
  strings:
    $key_8f50 = { db 38 [2] af 20 [2] e8 22 [2] af 33 [2] e1 3f [2] ed 35 [2] fa 3e [2] e1 70 [2] dc }

  condition:
    any of them
}