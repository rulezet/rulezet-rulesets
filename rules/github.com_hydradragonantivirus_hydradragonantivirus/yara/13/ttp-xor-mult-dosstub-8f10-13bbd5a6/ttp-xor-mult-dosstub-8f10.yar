rule TTP_XOR_MULT_DOSStub_8f10 {
  strings:
    $key_8f10 = { db 78 [2] af 60 [2] e8 62 [2] af 73 [2] e1 7f [2] ed 75 [2] fa 7e [2] e1 30 [2] dc }

  condition:
    any of them
}