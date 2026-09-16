rule TTP_XOR_MULT_DOSStub_efad {
  strings:
    $key_efad = { bb c5 [2] cf dd [2] 88 df [2] cf ce [2] 81 c2 [2] 8d c8 [2] 9a c3 [2] 81 8d [2] bc }

  condition:
    any of them
}