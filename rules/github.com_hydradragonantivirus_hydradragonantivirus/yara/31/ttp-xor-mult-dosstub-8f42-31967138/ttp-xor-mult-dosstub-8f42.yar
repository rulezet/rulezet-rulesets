rule TTP_XOR_MULT_DOSStub_8f42 {
  strings:
    $key_8f42 = { db 2a [2] af 32 [2] e8 30 [2] af 21 [2] e1 2d [2] ed 27 [2] fa 2c [2] e1 62 [2] dc }

  condition:
    any of them
}