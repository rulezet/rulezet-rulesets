rule TTP_XOR_MULT_DOSStub_7318 {
  strings:
    $key_7318 = { 27 70 [2] 53 68 [2] 14 6a [2] 53 7b [2] 1d 77 [2] 11 7d [2] 06 76 [2] 1d 38 [2] 20 }

  condition:
    any of them
}