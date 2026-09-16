rule TTP_XOR_MULT_DOSStub_8f1d {
  strings:
    $key_8f1d = { db 75 [2] af 6d [2] e8 6f [2] af 7e [2] e1 72 [2] ed 78 [2] fa 73 [2] e1 3d [2] dc }

  condition:
    any of them
}