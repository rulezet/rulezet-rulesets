rule TTP_XOR_MULT_DOSStub_7f63 {
  strings:
    $key_7f63 = { 2b 0b [2] 5f 13 [2] 18 11 [2] 5f 00 [2] 11 0c [2] 1d 06 [2] 0a 0d [2] 11 43 [2] 2c }

  condition:
    any of them
}