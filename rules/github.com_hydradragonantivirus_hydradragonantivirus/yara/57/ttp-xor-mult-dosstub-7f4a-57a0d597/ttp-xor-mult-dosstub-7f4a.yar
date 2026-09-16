rule TTP_XOR_MULT_DOSStub_7f4a {
  strings:
    $key_7f4a = { 2b 22 [2] 5f 3a [2] 18 38 [2] 5f 29 [2] 11 25 [2] 1d 2f [2] 0a 24 [2] 11 6a [2] 2c }

  condition:
    any of them
}