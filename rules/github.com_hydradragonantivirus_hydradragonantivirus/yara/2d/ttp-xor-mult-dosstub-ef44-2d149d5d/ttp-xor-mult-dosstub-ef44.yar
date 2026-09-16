rule TTP_XOR_MULT_DOSStub_ef44 {
  strings:
    $key_ef44 = { bb 2c [2] cf 34 [2] 88 36 [2] cf 27 [2] 81 2b [2] 8d 21 [2] 9a 2a [2] 81 64 [2] bc }

  condition:
    any of them
}