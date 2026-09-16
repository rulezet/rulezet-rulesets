rule TTP_XOR_MULT_DOSStub_7ff5 {
  strings:
    $key_7ff5 = { 2b 9d [2] 5f 85 [2] 18 87 [2] 5f 96 [2] 11 9a [2] 1d 90 [2] 0a 9b [2] 11 d5 [2] 2c }

  condition:
    any of them
}