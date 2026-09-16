rule TTP_XOR_MULT_DOSStub_8f4c {
  strings:
    $key_8f4c = { db 24 [2] af 3c [2] e8 3e [2] af 2f [2] e1 23 [2] ed 29 [2] fa 22 [2] e1 6c [2] dc }

  condition:
    any of them
}