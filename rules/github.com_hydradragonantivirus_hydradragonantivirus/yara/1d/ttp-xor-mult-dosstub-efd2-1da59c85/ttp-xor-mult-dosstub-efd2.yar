rule TTP_XOR_MULT_DOSStub_efd2 {
  strings:
    $key_efd2 = { bb ba [2] cf a2 [2] 88 a0 [2] cf b1 [2] 81 bd [2] 8d b7 [2] 9a bc [2] 81 f2 [2] bc }

  condition:
    any of them
}