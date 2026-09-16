rule TTP_XOR_MULT_DOSStub_8f00 {
  strings:
    $key_8f00 = { db 68 [2] af 70 [2] e8 72 [2] af 63 [2] e1 6f [2] ed 65 [2] fa 6e [2] e1 20 [2] dc }

  condition:
    any of them
}