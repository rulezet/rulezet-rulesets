rule TTP_XOR_MULT_DOSStub_1645 {
  strings:
    $key_1645 = { 42 2d [2] 36 35 [2] 71 37 [2] 36 26 [2] 78 2a [2] 74 20 [2] 63 2b [2] 78 65 [2] 45 }

  condition:
    any of them
}