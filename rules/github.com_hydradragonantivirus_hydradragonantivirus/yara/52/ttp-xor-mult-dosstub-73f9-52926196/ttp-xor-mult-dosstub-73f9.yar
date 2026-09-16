rule TTP_XOR_MULT_DOSStub_73f9 {
  strings:
    $key_73f9 = { 27 91 [2] 53 89 [2] 14 8b [2] 53 9a [2] 1d 96 [2] 11 9c [2] 06 97 [2] 1d d9 [2] 20 }

  condition:
    any of them
}