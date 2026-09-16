rule TTP_XOR_MULT_DOSStub_8f39 {
  strings:
    $key_8f39 = { db 51 [2] af 49 [2] e8 4b [2] af 5a [2] e1 56 [2] ed 5c [2] fa 57 [2] e1 19 [2] dc }

  condition:
    any of them
}