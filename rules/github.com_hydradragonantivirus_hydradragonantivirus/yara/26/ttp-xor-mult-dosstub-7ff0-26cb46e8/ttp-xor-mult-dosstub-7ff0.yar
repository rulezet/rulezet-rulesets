rule TTP_XOR_MULT_DOSStub_7ff0 {
  strings:
    $key_7ff0 = { 2b 98 [2] 5f 80 [2] 18 82 [2] 5f 93 [2] 11 9f [2] 1d 95 [2] 0a 9e [2] 11 d0 [2] 2c }

  condition:
    any of them
}