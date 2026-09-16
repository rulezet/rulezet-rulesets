rule TTP_XOR_MULT_DOSStub_7f66 {
  strings:
    $key_7f66 = { 2b 0e [2] 5f 16 [2] 18 14 [2] 5f 05 [2] 11 09 [2] 1d 03 [2] 0a 08 [2] 11 46 [2] 2c }

  condition:
    any of them
}