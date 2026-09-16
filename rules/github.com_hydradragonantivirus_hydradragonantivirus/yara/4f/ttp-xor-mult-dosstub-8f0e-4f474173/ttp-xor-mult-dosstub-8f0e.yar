rule TTP_XOR_MULT_DOSStub_8f0e {
  strings:
    $key_8f0e = { db 66 [2] af 7e [2] e8 7c [2] af 6d [2] e1 61 [2] ed 6b [2] fa 60 [2] e1 2e [2] dc }

  condition:
    any of them
}