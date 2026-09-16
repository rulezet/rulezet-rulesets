rule TTP_XOR_MULT_DOSStub_5545 {
  strings:
    $key_5545 = { 01 2d [2] 75 35 [2] 32 37 [2] 75 26 [2] 3b 2a [2] 37 20 [2] 20 2b [2] 3b 65 [2] 06 }

  condition:
    any of them
}