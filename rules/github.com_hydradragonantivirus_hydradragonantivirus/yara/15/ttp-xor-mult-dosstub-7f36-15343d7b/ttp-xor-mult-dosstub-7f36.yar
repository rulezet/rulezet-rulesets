rule TTP_XOR_MULT_DOSStub_7f36 {
  strings:
    $key_7f36 = { 2b 5e [2] 5f 46 [2] 18 44 [2] 5f 55 [2] 11 59 [2] 1d 53 [2] 0a 58 [2] 11 16 [2] 2c }

  condition:
    any of them
}