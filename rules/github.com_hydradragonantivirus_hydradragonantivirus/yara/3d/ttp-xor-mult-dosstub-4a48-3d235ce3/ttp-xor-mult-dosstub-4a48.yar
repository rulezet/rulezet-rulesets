rule TTP_XOR_MULT_DOSStub_4a48 {
  strings:
    $key_4a48 = { 1e 20 [2] 6a 38 [2] 2d 3a [2] 6a 2b [2] 24 27 [2] 28 2d [2] 3f 26 [2] 24 68 [2] 19 }

  condition:
    any of them
}