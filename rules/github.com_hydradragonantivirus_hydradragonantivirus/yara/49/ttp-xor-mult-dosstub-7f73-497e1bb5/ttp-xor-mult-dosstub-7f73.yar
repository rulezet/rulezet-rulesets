rule TTP_XOR_MULT_DOSStub_7f73 {
  strings:
    $key_7f73 = { 2b 1b [2] 5f 03 [2] 18 01 [2] 5f 10 [2] 11 1c [2] 1d 16 [2] 0a 1d [2] 11 53 [2] 2c }

  condition:
    any of them
}