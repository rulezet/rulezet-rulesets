rule TTP_XOR_MULT_DOSStub_5d05 {
  strings:
    $key_5d05 = { 09 6d [2] 7d 75 [2] 3a 77 [2] 7d 66 [2] 33 6a [2] 3f 60 [2] 28 6b [2] 33 25 [2] 0e }

  condition:
    any of them
}