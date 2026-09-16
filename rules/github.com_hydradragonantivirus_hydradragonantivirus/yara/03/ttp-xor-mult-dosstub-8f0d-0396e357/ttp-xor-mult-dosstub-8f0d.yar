rule TTP_XOR_MULT_DOSStub_8f0d {
  strings:
    $key_8f0d = { db 65 [2] af 7d [2] e8 7f [2] af 6e [2] e1 62 [2] ed 68 [2] fa 63 [2] e1 2d [2] dc }

  condition:
    any of them
}