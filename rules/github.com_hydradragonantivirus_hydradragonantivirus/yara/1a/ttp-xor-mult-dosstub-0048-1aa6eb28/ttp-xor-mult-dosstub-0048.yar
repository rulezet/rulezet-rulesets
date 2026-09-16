rule TTP_XOR_MULT_DOSStub_0048 {
  strings:
    $key_0048 = { 54 20 [2] 20 38 [2] 67 3a [2] 20 2b [2] 6e 27 [2] 62 2d [2] 75 26 [2] 6e 68 [2] 53 }

  condition:
    any of them
}