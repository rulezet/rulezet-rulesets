rule TTP_XOR_MULT_DOSStub_1248 {
  strings:
    $key_1248 = { 46 20 [2] 32 38 [2] 75 3a [2] 32 2b [2] 7c 27 [2] 70 2d [2] 67 26 [2] 7c 68 [2] 41 }

  condition:
    any of them
}