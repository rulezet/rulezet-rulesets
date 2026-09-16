rule TTP_XOR_MULT_DOSStub_ef48 {
  strings:
    $key_ef48 = { bb 20 [2] cf 38 [2] 88 3a [2] cf 2b [2] 81 27 [2] 8d 2d [2] 9a 26 [2] 81 68 [2] bc }

  condition:
    any of them
}