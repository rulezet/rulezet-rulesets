rule TTP_XOR_MULT_DOSStub_ef45 {
  strings:
    $key_ef45 = { bb 2d [2] cf 35 [2] 88 37 [2] cf 26 [2] 81 2a [2] 8d 20 [2] 9a 2b [2] 81 65 [2] bc }

  condition:
    any of them
}