rule TTP_XOR_MULT_DOSStub_1048 {
  strings:
    $key_1048 = { 44 20 [2] 30 38 [2] 77 3a [2] 30 2b [2] 7e 27 [2] 72 2d [2] 65 26 [2] 7e 68 [2] 43 }

  condition:
    any of them
}