rule TTP_XOR_MULT_DOSStub_2275 {
  strings:
    $key_2275 = { 76 1d [2] 02 05 [2] 45 07 [2] 02 16 [2] 4c 1a [2] 40 10 [2] 57 1b [2] 4c 55 [2] 71 }

  condition:
    any of them
}