rule TTP_XOR_MULT_DOSStub_423b {
  strings:
    $key_423b = { 16 53 [2] 62 4b [2] 25 49 [2] 62 58 [2] 2c 54 [2] 20 5e [2] 37 55 [2] 2c 1b [2] 11 }

  condition:
    any of them
}