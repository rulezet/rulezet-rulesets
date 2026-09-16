rule TTP_XOR_MULT_DOSStub_7a75 {
  strings:
    $key_7a75 = { 2e 1d [2] 5a 05 [2] 1d 07 [2] 5a 16 [2] 14 1a [2] 18 10 [2] 0f 1b [2] 14 55 [2] 29 }

  condition:
    any of them
}