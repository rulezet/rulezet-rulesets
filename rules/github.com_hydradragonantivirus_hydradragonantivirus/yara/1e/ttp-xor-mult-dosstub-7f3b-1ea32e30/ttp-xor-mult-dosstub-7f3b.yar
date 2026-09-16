rule TTP_XOR_MULT_DOSStub_7f3b {
  strings:
    $key_7f3b = { 2b 53 [2] 5f 4b [2] 18 49 [2] 5f 58 [2] 11 54 [2] 1d 5e [2] 0a 55 [2] 11 1b [2] 2c }

  condition:
    any of them
}