rule TTP_XOR_MULT_DOSStub_8f33 {
  strings:
    $key_8f33 = { db 5b [2] af 43 [2] e8 41 [2] af 50 [2] e1 5c [2] ed 56 [2] fa 5d [2] e1 13 [2] dc }

  condition:
    any of them
}