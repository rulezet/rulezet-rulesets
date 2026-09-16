rule TTP_XOR_MULT_DOSStub_7f79 {
  strings:
    $key_7f79 = { 2b 11 [2] 5f 09 [2] 18 0b [2] 5f 1a [2] 11 16 [2] 1d 1c [2] 0a 17 [2] 11 59 [2] 2c }

  condition:
    any of them
}