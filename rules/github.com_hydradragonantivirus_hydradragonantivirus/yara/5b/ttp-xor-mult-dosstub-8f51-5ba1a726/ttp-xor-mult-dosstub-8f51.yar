rule TTP_XOR_MULT_DOSStub_8f51 {
  strings:
    $key_8f51 = { db 39 [2] af 21 [2] e8 23 [2] af 32 [2] e1 3e [2] ed 34 [2] fa 3f [2] e1 71 [2] dc }

  condition:
    any of them
}