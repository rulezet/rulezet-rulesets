rule TTP_XOR_MULT_DOSStub_5408 {
  strings:
    $key_5408 = { 00 60 [2] 74 78 [2] 33 7a [2] 74 6b [2] 3a 67 [2] 36 6d [2] 21 66 [2] 3a 28 [2] 07 }

  condition:
    any of them
}