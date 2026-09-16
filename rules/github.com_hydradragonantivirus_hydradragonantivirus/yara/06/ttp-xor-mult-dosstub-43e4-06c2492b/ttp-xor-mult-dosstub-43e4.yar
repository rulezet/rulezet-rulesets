rule TTP_XOR_MULT_DOSStub_43e4 {
  strings:
    $key_43e4 = { 17 8c [2] 63 94 [2] 24 96 [2] 63 87 [2] 2d 8b [2] 21 81 [2] 36 8a [2] 2d c4 [2] 10 }

  condition:
    any of them
}