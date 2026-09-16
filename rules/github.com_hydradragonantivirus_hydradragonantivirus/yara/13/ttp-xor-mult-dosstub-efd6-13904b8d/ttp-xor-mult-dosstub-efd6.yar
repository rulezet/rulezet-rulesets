rule TTP_XOR_MULT_DOSStub_efd6 {
  strings:
    $key_efd6 = { bb be [2] cf a6 [2] 88 a4 [2] cf b5 [2] 81 b9 [2] 8d b3 [2] 9a b8 [2] 81 f6 [2] bc }

  condition:
    any of them
}