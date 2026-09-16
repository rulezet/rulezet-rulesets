rule TTP_XOR_MULT_DOSStub_0848 {
  strings:
    $key_0848 = { 5c 20 [2] 28 38 [2] 6f 3a [2] 28 2b [2] 66 27 [2] 6a 2d [2] 7d 26 [2] 66 68 [2] 5b }

  condition:
    any of them
}