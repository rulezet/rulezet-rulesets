rule TTP_XOR_MULT_DOSStub_8f79 {
  strings:
    $key_8f79 = { db 11 [2] af 09 [2] e8 0b [2] af 1a [2] e1 16 [2] ed 1c [2] fa 17 [2] e1 59 [2] dc }

  condition:
    any of them
}