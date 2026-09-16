rule TTP_XOR_MULT_DOSStub_3645 {
  strings:
    $key_3645 = { 62 2d [2] 16 35 [2] 51 37 [2] 16 26 [2] 58 2a [2] 54 20 [2] 43 2b [2] 58 65 [2] 65 }

  condition:
    any of them
}