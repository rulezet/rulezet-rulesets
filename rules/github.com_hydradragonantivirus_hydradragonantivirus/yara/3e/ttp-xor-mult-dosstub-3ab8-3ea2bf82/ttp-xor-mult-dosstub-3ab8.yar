rule TTP_XOR_MULT_DOSStub_3ab8 {
  strings:
    $key_3ab8 = { 6e d0 [2] 1a c8 [2] 5d ca [2] 1a db [2] 54 d7 [2] 58 dd [2] 4f d6 [2] 54 98 [2] 69 }

  condition:
    any of them
}