rule TTP_XOR_MULT_DOSStub_8f35 {
  strings:
    $key_8f35 = { db 5d [2] af 45 [2] e8 47 [2] af 56 [2] e1 5a [2] ed 50 [2] fa 5b [2] e1 15 [2] dc }

  condition:
    any of them
}