rule TTP_XOR_MULT_DOSStub_8f19 {
  strings:
    $key_8f19 = { db 71 [2] af 69 [2] e8 6b [2] af 7a [2] e1 76 [2] ed 7c [2] fa 77 [2] e1 39 [2] dc }

  condition:
    any of them
}