rule TTP_XOR_MULT_DOSStub_43e9 {
  strings:
    $key_43e9 = { 17 81 [2] 63 99 [2] 24 9b [2] 63 8a [2] 2d 86 [2] 21 8c [2] 36 87 [2] 2d c9 [2] 10 }

  condition:
    any of them
}