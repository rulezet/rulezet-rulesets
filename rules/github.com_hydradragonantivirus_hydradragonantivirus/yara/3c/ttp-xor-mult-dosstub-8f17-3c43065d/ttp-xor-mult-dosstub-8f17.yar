rule TTP_XOR_MULT_DOSStub_8f17 {
  strings:
    $key_8f17 = { db 7f [2] af 67 [2] e8 65 [2] af 74 [2] e1 78 [2] ed 72 [2] fa 79 [2] e1 37 [2] dc }

  condition:
    any of them
}