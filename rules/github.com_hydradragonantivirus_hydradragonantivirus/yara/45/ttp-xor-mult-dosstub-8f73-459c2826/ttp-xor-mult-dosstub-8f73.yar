rule TTP_XOR_MULT_DOSStub_8f73 {
  strings:
    $key_8f73 = { db 1b [2] af 03 [2] e8 01 [2] af 10 [2] e1 1c [2] ed 16 [2] fa 1d [2] e1 53 [2] dc }

  condition:
    any of them
}