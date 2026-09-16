rule TTP_XOR_MULT_DOSStub_ef78 {
  strings:
    $key_ef78 = { bb 10 [2] cf 08 [2] 88 0a [2] cf 1b [2] 81 17 [2] 8d 1d [2] 9a 16 [2] 81 58 [2] bc }

  condition:
    any of them
}