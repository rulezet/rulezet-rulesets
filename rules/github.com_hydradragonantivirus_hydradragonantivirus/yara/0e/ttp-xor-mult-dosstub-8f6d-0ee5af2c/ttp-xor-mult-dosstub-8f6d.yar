rule TTP_XOR_MULT_DOSStub_8f6d {
  strings:
    $key_8f6d = { db 05 [2] af 1d [2] e8 1f [2] af 0e [2] e1 02 [2] ed 08 [2] fa 03 [2] e1 4d [2] dc }

  condition:
    any of them
}