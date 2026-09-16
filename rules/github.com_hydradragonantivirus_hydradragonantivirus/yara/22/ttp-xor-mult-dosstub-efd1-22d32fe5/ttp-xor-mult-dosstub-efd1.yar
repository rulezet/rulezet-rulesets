rule TTP_XOR_MULT_DOSStub_efd1 {
  strings:
    $key_efd1 = { bb b9 [2] cf a1 [2] 88 a3 [2] cf b2 [2] 81 be [2] 8d b4 [2] 9a bf [2] 81 f1 [2] bc }

  condition:
    any of them
}