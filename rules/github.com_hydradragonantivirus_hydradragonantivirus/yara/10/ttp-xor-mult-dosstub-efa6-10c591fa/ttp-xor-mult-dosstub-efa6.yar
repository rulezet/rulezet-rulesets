rule TTP_XOR_MULT_DOSStub_efa6 {
  strings:
    $key_efa6 = { bb ce [2] cf d6 [2] 88 d4 [2] cf c5 [2] 81 c9 [2] 8d c3 [2] 9a c8 [2] 81 86 [2] bc }

  condition:
    any of them
}