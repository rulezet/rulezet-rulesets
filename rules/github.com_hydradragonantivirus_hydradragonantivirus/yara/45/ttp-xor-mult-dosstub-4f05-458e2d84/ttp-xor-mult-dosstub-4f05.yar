rule TTP_XOR_MULT_DOSStub_4f05 {
  strings:
    $key_4f05 = { 1b 6d [2] 6f 75 [2] 28 77 [2] 6f 66 [2] 21 6a [2] 2d 60 [2] 3a 6b [2] 21 25 [2] 1c }

  condition:
    any of them
}