rule TTP_XOR_MULT_DOSStub_8ffb {
  strings:
    $key_8ffb = { db 93 [2] af 8b [2] e8 89 [2] af 98 [2] e1 94 [2] ed 9e [2] fa 95 [2] e1 db [2] dc }

  condition:
    any of them
}