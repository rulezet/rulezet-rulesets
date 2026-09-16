rule TTP_XOR_MULT_DOSStub_8f4a {
  strings:
    $key_8f4a = { db 22 [2] af 3a [2] e8 38 [2] af 29 [2] e1 25 [2] ed 2f [2] fa 24 [2] e1 6a [2] dc }

  condition:
    any of them
}