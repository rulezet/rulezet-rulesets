rule TTP_XOR_MULT_DOSStub_5ab8 {
  strings:
    $key_5ab8 = { 0e d0 [2] 7a c8 [2] 3d ca [2] 7a db [2] 34 d7 [2] 38 dd [2] 2f d6 [2] 34 98 [2] 09 }

  condition:
    any of them
}