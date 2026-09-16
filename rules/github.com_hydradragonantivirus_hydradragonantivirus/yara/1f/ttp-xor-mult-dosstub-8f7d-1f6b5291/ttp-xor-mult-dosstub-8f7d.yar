rule TTP_XOR_MULT_DOSStub_8f7d {
  strings:
    $key_8f7d = { db 15 [2] af 0d [2] e8 0f [2] af 1e [2] e1 12 [2] ed 18 [2] fa 13 [2] e1 5d [2] dc }

  condition:
    any of them
}