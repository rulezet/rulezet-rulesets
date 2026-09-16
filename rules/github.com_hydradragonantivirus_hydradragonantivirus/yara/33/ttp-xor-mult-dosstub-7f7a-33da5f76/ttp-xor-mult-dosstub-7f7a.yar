rule TTP_XOR_MULT_DOSStub_7f7a {
  strings:
    $key_7f7a = { 2b 12 [2] 5f 0a [2] 18 08 [2] 5f 19 [2] 11 15 [2] 1d 1f [2] 0a 14 [2] 11 5a [2] 2c }

  condition:
    any of them
}