rule TTP_XOR_MULT_DOSStub_8f4f {
  strings:
    $key_8f4f = { db 27 [2] af 3f [2] e8 3d [2] af 2c [2] e1 20 [2] ed 2a [2] fa 21 [2] e1 6f [2] dc }

  condition:
    any of them
}