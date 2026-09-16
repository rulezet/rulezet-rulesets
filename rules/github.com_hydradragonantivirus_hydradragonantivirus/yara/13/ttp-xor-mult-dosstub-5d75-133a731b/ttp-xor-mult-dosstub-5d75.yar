rule TTP_XOR_MULT_DOSStub_5d75 {
  strings:
    $key_5d75 = { 09 1d [2] 7d 05 [2] 3a 07 [2] 7d 16 [2] 33 1a [2] 3f 10 [2] 28 1b [2] 33 55 [2] 0e }

  condition:
    any of them
}