rule TTP_XOR_MULT_DOSStub_7548 {
  strings:
    $key_7548 = { 21 20 [2] 55 38 [2] 12 3a [2] 55 2b [2] 1b 27 [2] 17 2d [2] 00 26 [2] 1b 68 [2] 26 }

  condition:
    any of them
}