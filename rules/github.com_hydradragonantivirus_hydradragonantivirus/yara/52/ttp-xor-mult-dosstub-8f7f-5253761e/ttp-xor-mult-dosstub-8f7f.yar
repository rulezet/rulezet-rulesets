rule TTP_XOR_MULT_DOSStub_8f7f {
  strings:
    $key_8f7f = { db 17 [2] af 0f [2] e8 0d [2] af 1c [2] e1 10 [2] ed 1a [2] fa 11 [2] e1 5f [2] dc }

  condition:
    any of them
}