rule TTP_XOR_MULT_DOSStub_8f5d {
  strings:
    $key_8f5d = { db 35 [2] af 2d [2] e8 2f [2] af 3e [2] e1 32 [2] ed 38 [2] fa 33 [2] e1 7d [2] dc }

  condition:
    any of them
}