rule TTP_XOR_MULT_DOSStub_7865 {
  strings:
    $key_7865 = { 2c 0d [2] 58 15 [2] 1f 17 [2] 58 06 [2] 16 0a [2] 1a 00 [2] 0d 0b [2] 16 45 [2] 2b }

  condition:
    any of them
}