rule TTP_XOR_MULT_DOSStub_7368 {
  strings:
    $key_7368 = { 27 00 [2] 53 18 [2] 14 1a [2] 53 0b [2] 1d 07 [2] 11 0d [2] 06 06 [2] 1d 48 [2] 20 }

  condition:
    any of them
}