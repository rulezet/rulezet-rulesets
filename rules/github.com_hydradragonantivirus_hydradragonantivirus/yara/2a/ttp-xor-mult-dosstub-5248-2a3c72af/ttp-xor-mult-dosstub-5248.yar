rule TTP_XOR_MULT_DOSStub_5248 {
  strings:
    $key_5248 = { 06 20 [2] 72 38 [2] 35 3a [2] 72 2b [2] 3c 27 [2] 30 2d [2] 27 26 [2] 3c 68 [2] 01 }

  condition:
    any of them
}