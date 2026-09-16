rule TTP_XOR_MULT_DOSStub_2645 {
  strings:
    $key_2645 = { 72 2d [2] 06 35 [2] 41 37 [2] 06 26 [2] 48 2a [2] 44 20 [2] 53 2b [2] 48 65 [2] 75 }

  condition:
    any of them
}