rule TTP_XOR_MULT_DOSStub_7345 {
  strings:
    $key_7345 = { 27 2d [2] 53 35 [2] 14 37 [2] 53 26 [2] 1d 2a [2] 11 20 [2] 06 2b [2] 1d 65 [2] 20 }

  condition:
    any of them
}