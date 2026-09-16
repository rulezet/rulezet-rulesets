rule TTP_XOR_MULT_DOSStub_ef70 {
  strings:
    $key_ef70 = { bb 18 [2] cf 00 [2] 88 02 [2] cf 13 [2] 81 1f [2] 8d 15 [2] 9a 1e [2] 81 50 [2] bc }

  condition:
    any of them
}