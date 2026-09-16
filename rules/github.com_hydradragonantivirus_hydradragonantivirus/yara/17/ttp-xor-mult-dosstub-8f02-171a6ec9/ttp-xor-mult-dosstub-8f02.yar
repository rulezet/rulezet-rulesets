rule TTP_XOR_MULT_DOSStub_8f02 {
  strings:
    $key_8f02 = { db 6a [2] af 72 [2] e8 70 [2] af 61 [2] e1 6d [2] ed 67 [2] fa 6c [2] e1 22 [2] dc }

  condition:
    any of them
}