rule TTP_XOR_MULT_DOSStub_8f46 {
  strings:
    $key_8f46 = { db 2e [2] af 36 [2] e8 34 [2] af 25 [2] e1 29 [2] ed 23 [2] fa 28 [2] e1 66 [2] dc }

  condition:
    any of them
}