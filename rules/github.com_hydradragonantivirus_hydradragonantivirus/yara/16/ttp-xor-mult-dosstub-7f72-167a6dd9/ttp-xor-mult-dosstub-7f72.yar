rule TTP_XOR_MULT_DOSStub_7f72 {
  strings:
    $key_7f72 = { 2b 1a [2] 5f 02 [2] 18 00 [2] 5f 11 [2] 11 1d [2] 1d 17 [2] 0a 1c [2] 11 52 [2] 2c }

  condition:
    any of them
}