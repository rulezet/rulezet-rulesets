rule TTP_XOR_MULT_DOSStub_7f59 {
  strings:
    $key_7f59 = { 2b 31 [2] 5f 29 [2] 18 2b [2] 5f 3a [2] 11 36 [2] 1d 3c [2] 0a 37 [2] 11 79 [2] 2c }

  condition:
    any of them
}