rule TTP_XOR_MULT_DOSStub_ef46 {
  strings:
    $key_ef46 = { bb 2e [2] cf 36 [2] 88 34 [2] cf 25 [2] 81 29 [2] 8d 23 [2] 9a 28 [2] 81 66 [2] bc }

  condition:
    any of them
}