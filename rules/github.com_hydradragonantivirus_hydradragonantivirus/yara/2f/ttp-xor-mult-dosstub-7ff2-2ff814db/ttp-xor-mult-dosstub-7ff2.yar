rule TTP_XOR_MULT_DOSStub_7ff2 {
  strings:
    $key_7ff2 = { 2b 9a [2] 5f 82 [2] 18 80 [2] 5f 91 [2] 11 9d [2] 1d 97 [2] 0a 9c [2] 11 d2 [2] 2c }

  condition:
    any of them
}