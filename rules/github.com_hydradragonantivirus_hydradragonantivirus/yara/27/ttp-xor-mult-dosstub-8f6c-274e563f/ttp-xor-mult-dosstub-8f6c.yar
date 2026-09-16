rule TTP_XOR_MULT_DOSStub_8f6c {
  strings:
    $key_8f6c = { db 04 [2] af 1c [2] e8 1e [2] af 0f [2] e1 03 [2] ed 09 [2] fa 02 [2] e1 4c [2] dc }

  condition:
    any of them
}