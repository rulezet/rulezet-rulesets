rule TTP_XOR_MULT_DOSStub_8f29 {
  strings:
    $key_8f29 = { db 41 [2] af 59 [2] e8 5b [2] af 4a [2] e1 46 [2] ed 4c [2] fa 47 [2] e1 09 [2] dc }

  condition:
    any of them
}