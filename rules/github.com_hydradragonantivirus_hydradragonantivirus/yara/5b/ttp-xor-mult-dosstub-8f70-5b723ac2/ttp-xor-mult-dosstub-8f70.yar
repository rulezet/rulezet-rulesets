rule TTP_XOR_MULT_DOSStub_8f70 {
  strings:
    $key_8f70 = { db 18 [2] af 00 [2] e8 02 [2] af 13 [2] e1 1f [2] ed 15 [2] fa 1e [2] e1 50 [2] dc }

  condition:
    any of them
}