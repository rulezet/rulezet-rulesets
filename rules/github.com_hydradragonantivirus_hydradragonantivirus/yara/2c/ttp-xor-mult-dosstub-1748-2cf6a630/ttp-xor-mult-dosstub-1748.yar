rule TTP_XOR_MULT_DOSStub_1748 {
  strings:
    $key_1748 = { 43 20 [2] 37 38 [2] 70 3a [2] 37 2b [2] 79 27 [2] 75 2d [2] 62 26 [2] 79 68 [2] 44 }

  condition:
    any of them
}