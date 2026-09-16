rule TTP_XOR_MULT_DOSStub_8f78 {
  strings:
    $key_8f78 = { db 10 [2] af 08 [2] e8 0a [2] af 1b [2] e1 17 [2] ed 1d [2] fa 16 [2] e1 58 [2] dc }

  condition:
    any of them
}