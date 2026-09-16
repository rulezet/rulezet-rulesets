rule TTP_XOR_MULT_DOSStub_8f4b {
  strings:
    $key_8f4b = { db 23 [2] af 3b [2] e8 39 [2] af 28 [2] e1 24 [2] ed 2e [2] fa 25 [2] e1 6b [2] dc }

  condition:
    any of them
}