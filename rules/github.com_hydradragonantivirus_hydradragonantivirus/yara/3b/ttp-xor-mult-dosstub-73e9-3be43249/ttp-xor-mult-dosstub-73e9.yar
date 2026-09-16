rule TTP_XOR_MULT_DOSStub_73e9 {
  strings:
    $key_73e9 = { 27 81 [2] 53 99 [2] 14 9b [2] 53 8a [2] 1d 86 [2] 11 8c [2] 06 87 [2] 1d c9 [2] 20 }

  condition:
    any of them
}