rule TTP_XOR_MULT_DOSStub_7f05 {
  strings:
    $key_7f05 = { 2b 6d [2] 5f 75 [2] 18 77 [2] 5f 66 [2] 11 6a [2] 1d 60 [2] 0a 6b [2] 11 25 [2] 2c }

  condition:
    any of them
}