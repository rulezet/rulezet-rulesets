rule TTP_XOR_MULT_DOSStub_7ff9 {
  strings:
    $key_7ff9 = { 2b 91 [2] 5f 89 [2] 18 8b [2] 5f 9a [2] 11 96 [2] 1d 9c [2] 0a 97 [2] 11 d9 [2] 2c }

  condition:
    any of them
}