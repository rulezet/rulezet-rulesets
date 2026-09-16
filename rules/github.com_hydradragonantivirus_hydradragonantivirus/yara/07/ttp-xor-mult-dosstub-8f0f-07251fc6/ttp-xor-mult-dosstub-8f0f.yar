rule TTP_XOR_MULT_DOSStub_8f0f {
  strings:
    $key_8f0f = { db 67 [2] af 7f [2] e8 7d [2] af 6c [2] e1 60 [2] ed 6a [2] fa 61 [2] e1 2f [2] dc }

  condition:
    any of them
}