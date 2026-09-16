rule TTP_XOR_MULT_DOSStub_5145 {
  strings:
    $key_5145 = { 05 2d [2] 71 35 [2] 36 37 [2] 71 26 [2] 3f 2a [2] 33 20 [2] 24 2b [2] 3f 65 [2] 02 }

  condition:
    any of them
}