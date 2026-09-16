rule TTP_XOR_MULT_DOSStub_8f61 {
  strings:
    $key_8f61 = { db 09 [2] af 11 [2] e8 13 [2] af 02 [2] e1 0e [2] ed 04 [2] fa 0f [2] e1 41 [2] dc }

  condition:
    any of them
}