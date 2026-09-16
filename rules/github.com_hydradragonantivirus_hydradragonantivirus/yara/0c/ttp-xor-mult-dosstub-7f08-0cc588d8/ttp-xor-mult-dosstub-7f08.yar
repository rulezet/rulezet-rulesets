rule TTP_XOR_MULT_DOSStub_7f08 {
  strings:
    $key_7f08 = { 2b 60 [2] 5f 78 [2] 18 7a [2] 5f 6b [2] 11 67 [2] 1d 6d [2] 0a 66 [2] 11 28 [2] 2c }

  condition:
    any of them
}