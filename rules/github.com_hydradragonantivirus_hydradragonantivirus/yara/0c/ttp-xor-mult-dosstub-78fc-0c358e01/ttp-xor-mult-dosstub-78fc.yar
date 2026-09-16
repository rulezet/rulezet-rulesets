rule TTP_XOR_MULT_DOSStub_78fc {
  strings:
    $key_78fc = { 2c 94 [2] 58 8c [2] 1f 8e [2] 58 9f [2] 16 93 [2] 1a 99 [2] 0d 92 [2] 16 dc [2] 2b }

  condition:
    any of them
}