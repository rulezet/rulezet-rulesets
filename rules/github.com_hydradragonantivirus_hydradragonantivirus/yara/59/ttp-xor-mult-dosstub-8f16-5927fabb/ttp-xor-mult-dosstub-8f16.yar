rule TTP_XOR_MULT_DOSStub_8f16 {
  strings:
    $key_8f16 = { db 7e [2] af 66 [2] e8 64 [2] af 75 [2] e1 79 [2] ed 73 [2] fa 78 [2] e1 36 [2] dc }

  condition:
    any of them
}