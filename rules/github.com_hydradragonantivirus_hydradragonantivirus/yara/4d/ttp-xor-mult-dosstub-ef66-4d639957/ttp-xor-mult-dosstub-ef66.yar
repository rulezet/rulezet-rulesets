rule TTP_XOR_MULT_DOSStub_ef66 {
  strings:
    $key_ef66 = { bb 0e [2] cf 16 [2] 88 14 [2] cf 05 [2] 81 09 [2] 8d 03 [2] 9a 08 [2] 81 46 [2] bc }

  condition:
    any of them
}