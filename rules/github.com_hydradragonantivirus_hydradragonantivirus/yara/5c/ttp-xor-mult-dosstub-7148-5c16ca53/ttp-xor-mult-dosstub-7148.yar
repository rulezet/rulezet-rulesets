rule TTP_XOR_MULT_DOSStub_7148 {
  strings:
    $key_7148 = { 25 20 [2] 51 38 [2] 16 3a [2] 51 2b [2] 1f 27 [2] 13 2d [2] 04 26 [2] 1f 68 [2] 22 }

  condition:
    any of them
}