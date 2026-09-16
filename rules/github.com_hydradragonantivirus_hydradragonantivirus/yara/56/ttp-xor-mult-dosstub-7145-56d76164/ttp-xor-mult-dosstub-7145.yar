rule TTP_XOR_MULT_DOSStub_7145 {
  strings:
    $key_7145 = { 25 2d [2] 51 35 [2] 16 37 [2] 51 26 [2] 1f 2a [2] 13 20 [2] 04 2b [2] 1f 65 [2] 22 }

  condition:
    any of them
}