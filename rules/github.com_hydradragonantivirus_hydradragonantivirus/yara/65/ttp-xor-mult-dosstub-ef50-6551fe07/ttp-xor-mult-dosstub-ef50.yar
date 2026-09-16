rule TTP_XOR_MULT_DOSStub_ef50 {
  strings:
    $key_ef50 = { bb 38 [2] cf 20 [2] 88 22 [2] cf 33 [2] 81 3f [2] 8d 35 [2] 9a 3e [2] 81 70 [2] bc }

  condition:
    any of them
}