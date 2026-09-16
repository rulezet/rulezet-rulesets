rule TTP_XOR_MULT_DOSStub_2a75 {
  strings:
    $key_2a75 = { 7e 1d [2] 0a 05 [2] 4d 07 [2] 0a 16 [2] 44 1a [2] 48 10 [2] 5f 1b [2] 44 55 [2] 79 }

  condition:
    any of them
}