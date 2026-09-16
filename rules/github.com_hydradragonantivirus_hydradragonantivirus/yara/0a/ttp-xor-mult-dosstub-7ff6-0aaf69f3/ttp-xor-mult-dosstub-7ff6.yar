rule TTP_XOR_MULT_DOSStub_7ff6 {
  strings:
    $key_7ff6 = { 2b 9e [2] 5f 86 [2] 18 84 [2] 5f 95 [2] 11 99 [2] 1d 93 [2] 0a 98 [2] 11 d6 [2] 2c }

  condition:
    any of them
}