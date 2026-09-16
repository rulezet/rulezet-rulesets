rule TTP_XOR_MULT_DOSStub_7f50 {
  strings:
    $key_7f50 = { 2b 38 [2] 5f 20 [2] 18 22 [2] 5f 33 [2] 11 3f [2] 1d 35 [2] 0a 3e [2] 11 70 [2] 2c }

  condition:
    any of them
}