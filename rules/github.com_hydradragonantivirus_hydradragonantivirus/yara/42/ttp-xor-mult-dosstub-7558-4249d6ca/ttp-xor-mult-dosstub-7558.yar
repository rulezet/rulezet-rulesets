rule TTP_XOR_MULT_DOSStub_7558 {
  strings:
    $key_7558 = { 21 30 [2] 55 28 [2] 12 2a [2] 55 3b [2] 1b 37 [2] 17 3d [2] 00 36 [2] 1b 78 [2] 26 }

  condition:
    any of them
}