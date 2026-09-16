rule TTP_XOR_MULT_DOSStub_8f5c {
  strings:
    $key_8f5c = { db 34 [2] af 2c [2] e8 2e [2] af 3f [2] e1 33 [2] ed 39 [2] fa 32 [2] e1 7c [2] dc }

  condition:
    any of them
}