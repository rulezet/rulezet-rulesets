rule TTP_XOR_MULT_DOSStub_8f13 {
  strings:
    $key_8f13 = { db 7b [2] af 63 [2] e8 61 [2] af 70 [2] e1 7c [2] ed 76 [2] fa 7d [2] e1 33 [2] dc }

  condition:
    any of them
}