rule TTP_XOR_MULT_DOSStub_7f3a {
  strings:
    $key_7f3a = { 2b 52 [2] 5f 4a [2] 18 48 [2] 5f 59 [2] 11 55 [2] 1d 5f [2] 0a 54 [2] 11 1a [2] 2c }

  condition:
    any of them
}