rule TTP_XOR_MULT_DOSStub_7f38 {
  strings:
    $key_7f38 = { 2b 50 [2] 5f 48 [2] 18 4a [2] 5f 5b [2] 11 57 [2] 1d 5d [2] 0a 56 [2] 11 18 [2] 2c }

  condition:
    any of them
}