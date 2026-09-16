rule TTP_XOR_MULT_DOSStub_7ff4 {
  strings:
    $key_7ff4 = { 2b 9c [2] 5f 84 [2] 18 86 [2] 5f 97 [2] 11 9b [2] 1d 91 [2] 0a 9a [2] 11 d4 [2] 2c }

  condition:
    any of them
}