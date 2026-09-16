rule TTP_XOR_MULT_DOSStub_8f24 {
  strings:
    $key_8f24 = { db 4c [2] af 54 [2] e8 56 [2] af 47 [2] e1 4b [2] ed 41 [2] fa 4a [2] e1 04 [2] dc }

  condition:
    any of them
}