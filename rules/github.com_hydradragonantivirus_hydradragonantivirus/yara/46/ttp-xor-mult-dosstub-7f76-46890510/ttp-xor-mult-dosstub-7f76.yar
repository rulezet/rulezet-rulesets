rule TTP_XOR_MULT_DOSStub_7f76 {
  strings:
    $key_7f76 = { 2b 1e [2] 5f 06 [2] 18 04 [2] 5f 15 [2] 11 19 [2] 1d 13 [2] 0a 18 [2] 11 56 [2] 2c }

  condition:
    any of them
}