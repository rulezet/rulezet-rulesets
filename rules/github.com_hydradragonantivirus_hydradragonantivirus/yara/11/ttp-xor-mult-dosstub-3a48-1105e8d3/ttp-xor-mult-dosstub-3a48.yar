rule TTP_XOR_MULT_DOSStub_3a48 {
  strings:
    $key_3a48 = { 6e 20 [2] 1a 38 [2] 5d 3a [2] 1a 2b [2] 54 27 [2] 58 2d [2] 4f 26 [2] 54 68 [2] 69 }

  condition:
    any of them
}