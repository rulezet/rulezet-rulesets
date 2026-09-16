rule TTP_XOR_MULT_DOSStub_7f5b {
  strings:
    $key_7f5b = { 2b 33 [2] 5f 2b [2] 18 29 [2] 5f 38 [2] 11 34 [2] 1d 3e [2] 0a 35 [2] 11 7b [2] 2c }

  condition:
    any of them
}