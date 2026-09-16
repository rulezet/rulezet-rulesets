rule TTP_XOR_MULT_DOSStub_8f3f {
  strings:
    $key_8f3f = { db 57 [2] af 4f [2] e8 4d [2] af 5c [2] e1 50 [2] ed 5a [2] fa 51 [2] e1 1f [2] dc }

  condition:
    any of them
}