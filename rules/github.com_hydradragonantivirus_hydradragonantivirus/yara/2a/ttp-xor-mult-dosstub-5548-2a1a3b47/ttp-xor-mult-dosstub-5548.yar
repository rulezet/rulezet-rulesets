rule TTP_XOR_MULT_DOSStub_5548 {
  strings:
    $key_5548 = { 01 20 [2] 75 38 [2] 32 3a [2] 75 2b [2] 3b 27 [2] 37 2d [2] 20 26 [2] 3b 68 [2] 06 }

  condition:
    any of them
}