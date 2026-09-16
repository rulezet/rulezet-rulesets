rule TTP_XOR_MULT_DOSStub_7815 {
  strings:
    $key_7815 = { 2c 7d [2] 58 65 [2] 1f 67 [2] 58 76 [2] 16 7a [2] 1a 70 [2] 0d 7b [2] 16 35 [2] 2b }

  condition:
    any of them
}