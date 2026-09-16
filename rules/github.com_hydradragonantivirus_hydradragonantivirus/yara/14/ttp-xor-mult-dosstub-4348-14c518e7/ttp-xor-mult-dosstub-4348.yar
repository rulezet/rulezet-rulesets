rule TTP_XOR_MULT_DOSStub_4348 {
  strings:
    $key_4348 = { 17 20 [2] 63 38 [2] 24 3a [2] 63 2b [2] 2d 27 [2] 21 2d [2] 36 26 [2] 2d 68 [2] 10 }

  condition:
    any of them
}