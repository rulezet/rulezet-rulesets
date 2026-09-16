rule TTP_XOR_MULT_DOSStub_7fa8 {
  strings:
    $key_7fa8 = { 2b c0 [2] 5f d8 [2] 18 da [2] 5f cb [2] 11 c7 [2] 1d cd [2] 0a c6 [2] 11 88 [2] 2c }

  condition:
    any of them
}