rule TTP_XOR_MULT_DOSStub_8f43 {
  strings:
    $key_8f43 = { db 2b [2] af 33 [2] e8 31 [2] af 20 [2] e1 2c [2] ed 26 [2] fa 2d [2] e1 63 [2] dc }

  condition:
    any of them
}