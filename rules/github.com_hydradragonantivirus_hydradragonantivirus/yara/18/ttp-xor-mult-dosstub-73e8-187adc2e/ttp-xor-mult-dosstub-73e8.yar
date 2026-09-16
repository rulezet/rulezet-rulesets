rule TTP_XOR_MULT_DOSStub_73e8 {
  strings:
    $key_73e8 = { 27 80 [2] 53 98 [2] 14 9a [2] 53 8b [2] 1d 87 [2] 11 8d [2] 06 86 [2] 1d c8 [2] 20 }

  condition:
    any of them
}