rule TTP_XOR_MULT_DOSStub_5a75 {
  strings:
    $key_5a75 = { 0e 1d [2] 7a 05 [2] 3d 07 [2] 7a 16 [2] 34 1a [2] 38 10 [2] 2f 1b [2] 34 55 [2] 09 }

  condition:
    any of them
}