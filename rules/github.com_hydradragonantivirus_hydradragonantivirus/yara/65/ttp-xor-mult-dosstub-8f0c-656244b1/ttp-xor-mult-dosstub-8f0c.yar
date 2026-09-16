rule TTP_XOR_MULT_DOSStub_8f0c {
  strings:
    $key_8f0c = { db 64 [2] af 7c [2] e8 7e [2] af 6f [2] e1 63 [2] ed 69 [2] fa 62 [2] e1 2c [2] dc }

  condition:
    any of them
}