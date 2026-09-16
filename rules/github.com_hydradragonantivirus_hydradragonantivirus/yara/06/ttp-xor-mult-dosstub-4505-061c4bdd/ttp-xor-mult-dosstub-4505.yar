rule TTP_XOR_MULT_DOSStub_4505 {
  strings:
    $key_4505 = { 11 6d [2] 65 75 [2] 22 77 [2] 65 66 [2] 2b 6a [2] 27 60 [2] 30 6b [2] 2b 25 [2] 16 }

  condition:
    any of them
}