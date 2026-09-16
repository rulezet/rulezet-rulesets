rule TTP_XOR_MULT_DOSStub_8f5a {
  strings:
    $key_8f5a = { db 32 [2] af 2a [2] e8 28 [2] af 39 [2] e1 35 [2] ed 3f [2] fa 34 [2] e1 7a [2] dc }

  condition:
    any of them
}