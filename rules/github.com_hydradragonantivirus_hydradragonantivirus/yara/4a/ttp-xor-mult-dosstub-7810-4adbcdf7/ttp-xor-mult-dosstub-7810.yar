rule TTP_XOR_MULT_DOSStub_7810 {
  strings:
    $key_7810 = { 2c 78 [2] 58 60 [2] 1f 62 [2] 58 73 [2] 16 7f [2] 1a 75 [2] 0d 7e [2] 16 30 [2] 2b }

  condition:
    any of them
}