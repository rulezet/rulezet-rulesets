rule TTP_XOR_MULT_DOSStub_78f5 {
  strings:
    $key_78f5 = { 2c 9d [2] 58 85 [2] 1f 87 [2] 58 96 [2] 16 9a [2] 1a 90 [2] 0d 9b [2] 16 d5 [2] 2b }

  condition:
    any of them
}