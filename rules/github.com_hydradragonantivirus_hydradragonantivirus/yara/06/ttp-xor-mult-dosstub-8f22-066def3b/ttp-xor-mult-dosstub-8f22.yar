rule TTP_XOR_MULT_DOSStub_8f22 {
  strings:
    $key_8f22 = { db 4a [2] af 52 [2] e8 50 [2] af 41 [2] e1 4d [2] ed 47 [2] fa 4c [2] e1 02 [2] dc }

  condition:
    any of them
}