rule TTP_XOR_MULT_DOSStub_8f72 {
  strings:
    $key_8f72 = { db 1a [2] af 02 [2] e8 00 [2] af 11 [2] e1 1d [2] ed 17 [2] fa 1c [2] e1 52 [2] dc }

  condition:
    any of them
}