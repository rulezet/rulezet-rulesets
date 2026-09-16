rule TTP_XOR_MULT_DOSStub_2375 {
  strings:
    $key_2375 = { 77 1d [2] 03 05 [2] 44 07 [2] 03 16 [2] 4d 1a [2] 41 10 [2] 56 1b [2] 4d 55 [2] 70 }

  condition:
    any of them
}