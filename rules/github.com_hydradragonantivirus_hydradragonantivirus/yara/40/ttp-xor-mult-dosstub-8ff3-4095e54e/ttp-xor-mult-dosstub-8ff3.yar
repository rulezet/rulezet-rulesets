rule TTP_XOR_MULT_DOSStub_8ff3 {
  strings:
    $key_8ff3 = { db 9b [2] af 83 [2] e8 81 [2] af 90 [2] e1 9c [2] ed 96 [2] fa 9d [2] e1 d3 [2] dc }

  condition:
    any of them
}