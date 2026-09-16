rule TTP_XOR_MULT_DOSStub_8f32 {
  strings:
    $key_8f32 = { db 5a [2] af 42 [2] e8 40 [2] af 51 [2] e1 5d [2] ed 57 [2] fa 5c [2] e1 12 [2] dc }

  condition:
    any of them
}