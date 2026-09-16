rule TTP_XOR_MULT_DOSStub_4d59 {
  strings:
    $key_4d59 = { 19 31 [2] 6d 29 [2] 2a 2b [2] 6d 3a [2] 23 36 [2] 2f 3c [2] 38 37 [2] 23 79 [2] 1e }

  condition:
    any of them
}