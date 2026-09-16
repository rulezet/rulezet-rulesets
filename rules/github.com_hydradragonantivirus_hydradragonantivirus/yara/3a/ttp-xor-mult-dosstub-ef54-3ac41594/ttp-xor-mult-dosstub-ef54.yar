rule TTP_XOR_MULT_DOSStub_ef54 {
  strings:
    $key_ef54 = { bb 3c [2] cf 24 [2] 88 26 [2] cf 37 [2] 81 3b [2] 8d 31 [2] 9a 3a [2] 81 74 [2] bc }

  condition:
    any of them
}