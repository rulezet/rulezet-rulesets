rule TTP_XOR_MULT_DOSStub_7379 {
  strings:
    $key_7379 = { 27 11 [2] 53 09 [2] 14 0b [2] 53 1a [2] 1d 16 [2] 11 1c [2] 06 17 [2] 1d 59 [2] 20 }

  condition:
    any of them
}