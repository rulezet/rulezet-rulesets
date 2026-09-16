rule TTP_XOR_MULT_DOSStub_ef63 {
  strings:
    $key_ef63 = { bb 0b [2] cf 13 [2] 88 11 [2] cf 00 [2] 81 0c [2] 8d 06 [2] 9a 0d [2] 81 43 [2] bc }

  condition:
    any of them
}