rule TTP_XOR_MULT_DOSStub_1a75 {
  strings:
    $key_1a75 = { 4e 1d [2] 3a 05 [2] 7d 07 [2] 3a 16 [2] 74 1a [2] 78 10 [2] 6f 1b [2] 74 55 [2] 49 }

  condition:
    any of them
}