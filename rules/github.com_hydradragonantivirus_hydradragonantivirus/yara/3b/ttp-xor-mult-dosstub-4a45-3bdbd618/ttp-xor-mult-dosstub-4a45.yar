rule TTP_XOR_MULT_DOSStub_4a45 {
  strings:
    $key_4a45 = { 1e 2d [2] 6a 35 [2] 2d 37 [2] 6a 26 [2] 24 2a [2] 28 20 [2] 3f 2b [2] 24 65 [2] 19 }

  condition:
    any of them
}