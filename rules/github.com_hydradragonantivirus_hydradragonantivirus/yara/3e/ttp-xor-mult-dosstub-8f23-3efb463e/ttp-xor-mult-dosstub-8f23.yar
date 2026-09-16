rule TTP_XOR_MULT_DOSStub_8f23 {
  strings:
    $key_8f23 = { db 4b [2] af 53 [2] e8 51 [2] af 40 [2] e1 4c [2] ed 46 [2] fa 4d [2] e1 03 [2] dc }

  condition:
    any of them
}