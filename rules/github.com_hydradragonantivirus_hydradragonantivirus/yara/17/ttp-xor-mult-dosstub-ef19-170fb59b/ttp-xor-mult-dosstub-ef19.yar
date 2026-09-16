rule TTP_XOR_MULT_DOSStub_ef19 {
  strings:
    $key_ef19 = { bb 71 [2] cf 69 [2] 88 6b [2] cf 7a [2] 81 76 [2] 8d 7c [2] 9a 77 [2] 81 39 [2] bc }

  condition:
    any of them
}