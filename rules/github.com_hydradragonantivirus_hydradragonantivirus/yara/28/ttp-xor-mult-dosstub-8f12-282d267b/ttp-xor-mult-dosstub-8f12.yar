rule TTP_XOR_MULT_DOSStub_8f12 {
  strings:
    $key_8f12 = { db 7a [2] af 62 [2] e8 60 [2] af 71 [2] e1 7d [2] ed 77 [2] fa 7c [2] e1 32 [2] dc }

  condition:
    any of them
}