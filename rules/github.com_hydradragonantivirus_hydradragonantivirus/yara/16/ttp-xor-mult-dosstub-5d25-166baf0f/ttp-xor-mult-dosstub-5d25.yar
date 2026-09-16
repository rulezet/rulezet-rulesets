rule TTP_XOR_MULT_DOSStub_5d25 {
  strings:
    $key_5d25 = { 09 4d [2] 7d 55 [2] 3a 57 [2] 7d 46 [2] 33 4a [2] 3f 40 [2] 28 4b [2] 33 05 [2] 0e }

  condition:
    any of them
}