rule TTP_XOR_MULT_DOSStub_8f60 {
  strings:
    $key_8f60 = { db 08 [2] af 10 [2] e8 12 [2] af 03 [2] e1 0f [2] ed 05 [2] fa 0e [2] e1 40 [2] dc }

  condition:
    any of them
}