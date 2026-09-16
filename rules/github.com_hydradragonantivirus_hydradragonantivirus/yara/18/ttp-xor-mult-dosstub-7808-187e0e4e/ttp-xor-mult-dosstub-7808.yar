rule TTP_XOR_MULT_DOSStub_7808 {
  strings:
    $key_7808 = { 2c 60 [2] 58 78 [2] 1f 7a [2] 58 6b [2] 16 67 [2] 1a 6d [2] 0d 66 [2] 16 28 [2] 2b }

  condition:
    any of them
}