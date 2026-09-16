rule TTP_XOR_MULT_DOSStub_73f8 {
  strings:
    $key_73f8 = { 27 90 [2] 53 88 [2] 14 8a [2] 53 9b [2] 1d 97 [2] 11 9d [2] 06 96 [2] 1d d8 [2] 20 }

  condition:
    any of them
}