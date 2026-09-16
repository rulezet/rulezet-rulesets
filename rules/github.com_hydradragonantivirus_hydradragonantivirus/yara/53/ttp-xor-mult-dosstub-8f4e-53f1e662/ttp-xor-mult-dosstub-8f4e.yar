rule TTP_XOR_MULT_DOSStub_8f4e {
  strings:
    $key_8f4e = { db 26 [2] af 3e [2] e8 3c [2] af 2d [2] e1 21 [2] ed 2b [2] fa 20 [2] e1 6e [2] dc }

  condition:
    any of them
}