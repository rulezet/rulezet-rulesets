rule TTP_XOR_MULT_DOSStub_efc8 {
  strings:
    $key_efc8 = { bb a0 [2] cf b8 [2] 88 ba [2] cf ab [2] 81 a7 [2] 8d ad [2] 9a a6 [2] 81 e8 [2] bc }

  condition:
    any of them
}