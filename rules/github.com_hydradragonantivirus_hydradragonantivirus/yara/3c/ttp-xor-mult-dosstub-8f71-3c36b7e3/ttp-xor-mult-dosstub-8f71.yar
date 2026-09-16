rule TTP_XOR_MULT_DOSStub_8f71 {
  strings:
    $key_8f71 = { db 19 [2] af 01 [2] e8 03 [2] af 12 [2] e1 1e [2] ed 14 [2] fa 1f [2] e1 51 [2] dc }

  condition:
    any of them
}