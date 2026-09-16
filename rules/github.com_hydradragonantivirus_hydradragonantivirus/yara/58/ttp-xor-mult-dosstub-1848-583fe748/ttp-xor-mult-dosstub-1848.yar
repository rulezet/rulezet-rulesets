rule TTP_XOR_MULT_DOSStub_1848 {
  strings:
    $key_1848 = { 4c 20 [2] 38 38 [2] 7f 3a [2] 38 2b [2] 76 27 [2] 7a 2d [2] 6d 26 [2] 76 68 [2] 4b }

  condition:
    any of them
}