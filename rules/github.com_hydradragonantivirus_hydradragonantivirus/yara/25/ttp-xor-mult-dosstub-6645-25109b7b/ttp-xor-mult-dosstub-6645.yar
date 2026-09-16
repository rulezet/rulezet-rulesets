rule TTP_XOR_MULT_DOSStub_6645 {
  strings:
    $key_6645 = { 32 2d [2] 46 35 [2] 01 37 [2] 46 26 [2] 08 2a [2] 04 20 [2] 13 2b [2] 08 65 [2] 35 }

  condition:
    any of them
}