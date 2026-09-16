rule TTP_XOR_MULT_DOSStub_8f3b {
  strings:
    $key_8f3b = { db 53 [2] af 4b [2] e8 49 [2] af 58 [2] e1 54 [2] ed 5e [2] fa 55 [2] e1 1b [2] dc }

  condition:
    any of them
}