rule TTP_XOR_MULT_DOSStub_5a45 {
  strings:
    $key_5a45 = { 0e 2d [2] 7a 35 [2] 3d 37 [2] 7a 26 [2] 34 2a [2] 38 20 [2] 2f 2b [2] 34 65 [2] 09 }

  condition:
    any of them
}