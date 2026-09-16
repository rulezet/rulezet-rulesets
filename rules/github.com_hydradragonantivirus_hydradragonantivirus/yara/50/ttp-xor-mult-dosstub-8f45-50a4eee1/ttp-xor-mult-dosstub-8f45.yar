rule TTP_XOR_MULT_DOSStub_8f45 {
  strings:
    $key_8f45 = { db 2d [2] af 35 [2] e8 37 [2] af 26 [2] e1 2a [2] ed 20 [2] fa 2b [2] e1 65 [2] dc }

  condition:
    any of them
}