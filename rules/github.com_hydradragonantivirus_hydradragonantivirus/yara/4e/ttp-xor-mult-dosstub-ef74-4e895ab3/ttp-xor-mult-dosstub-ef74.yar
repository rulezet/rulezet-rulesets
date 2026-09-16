rule TTP_XOR_MULT_DOSStub_ef74 {
  strings:
    $key_ef74 = { bb 1c [2] cf 04 [2] 88 06 [2] cf 17 [2] 81 1b [2] 8d 11 [2] 9a 1a [2] 81 54 [2] bc }

  condition:
    any of them
}