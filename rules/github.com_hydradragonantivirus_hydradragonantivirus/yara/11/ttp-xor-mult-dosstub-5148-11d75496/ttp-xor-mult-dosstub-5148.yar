rule TTP_XOR_MULT_DOSStub_5148 {
  strings:
    $key_5148 = { 05 20 [2] 71 38 [2] 36 3a [2] 71 2b [2] 3f 27 [2] 33 2d [2] 24 26 [2] 3f 68 [2] 02 }

  condition:
    any of them
}