rule TTP_XOR_MULT_DOSStub_ef49 {
  strings:
    $key_ef49 = { bb 21 [2] cf 39 [2] 88 3b [2] cf 2a [2] 81 26 [2] 8d 2c [2] 9a 27 [2] 81 69 [2] bc }

  condition:
    any of them
}