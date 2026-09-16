rule TTP_XOR_MULT_DOSStub_8f57 {
  strings:
    $key_8f57 = { db 3f [2] af 27 [2] e8 25 [2] af 34 [2] e1 38 [2] ed 32 [2] fa 39 [2] e1 77 [2] dc }

  condition:
    any of them
}