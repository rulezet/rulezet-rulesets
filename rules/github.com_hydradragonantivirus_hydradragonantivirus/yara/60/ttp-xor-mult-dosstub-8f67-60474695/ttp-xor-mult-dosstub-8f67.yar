rule TTP_XOR_MULT_DOSStub_8f67 {
  strings:
    $key_8f67 = { db 0f [2] af 17 [2] e8 15 [2] af 04 [2] e1 08 [2] ed 02 [2] fa 09 [2] e1 47 [2] dc }

  condition:
    any of them
}