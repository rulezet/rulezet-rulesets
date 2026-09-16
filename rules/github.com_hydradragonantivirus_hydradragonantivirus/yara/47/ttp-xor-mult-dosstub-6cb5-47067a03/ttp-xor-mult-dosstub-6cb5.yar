rule TTP_XOR_MULT_DOSStub_6cb5 {
  strings:
    $key_6cb5 = { 38 dd [2] 4c c5 [2] 0b c7 [2] 4c d6 [2] 02 da [2] 0e d0 [2] 19 db [2] 02 95 [2] 3f }

  condition:
    any of them
}