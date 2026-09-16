rule TTP_XOR_MULT_DOSStub_8f3c {
  strings:
    $key_8f3c = { db 54 [2] af 4c [2] e8 4e [2] af 5f [2] e1 53 [2] ed 59 [2] fa 52 [2] e1 1c [2] dc }

  condition:
    any of them
}