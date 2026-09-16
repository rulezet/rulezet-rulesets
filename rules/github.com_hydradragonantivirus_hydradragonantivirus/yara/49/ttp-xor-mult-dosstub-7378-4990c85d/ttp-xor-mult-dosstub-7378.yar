rule TTP_XOR_MULT_DOSStub_7378 {
  strings:
    $key_7378 = { 27 10 [2] 53 08 [2] 14 0a [2] 53 1b [2] 1d 17 [2] 11 1d [2] 06 16 [2] 1d 58 [2] 20 }

  condition:
    any of them
}