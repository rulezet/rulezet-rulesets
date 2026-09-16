rule TTP_XOR_MULT_DOSStub_8ffd {
  strings:
    $key_8ffd = { db 95 [2] af 8d [2] e8 8f [2] af 9e [2] e1 92 [2] ed 98 [2] fa 93 [2] e1 dd [2] dc }

  condition:
    any of them
}