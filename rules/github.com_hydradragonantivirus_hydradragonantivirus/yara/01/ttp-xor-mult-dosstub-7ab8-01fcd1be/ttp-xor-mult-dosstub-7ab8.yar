rule TTP_XOR_MULT_DOSStub_7ab8 {
  strings:
    $key_7ab8 = { 2e d0 [2] 5a c8 [2] 1d ca [2] 5a db [2] 14 d7 [2] 18 dd [2] 0f d6 [2] 14 98 [2] 29 }

  condition:
    any of them
}