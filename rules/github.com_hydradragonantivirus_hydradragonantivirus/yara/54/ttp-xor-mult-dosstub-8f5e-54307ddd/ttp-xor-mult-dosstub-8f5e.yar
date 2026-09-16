rule TTP_XOR_MULT_DOSStub_8f5e {
  strings:
    $key_8f5e = { db 36 [2] af 2e [2] e8 2c [2] af 3d [2] e1 31 [2] ed 3b [2] fa 30 [2] e1 7e [2] dc }

  condition:
    any of them
}