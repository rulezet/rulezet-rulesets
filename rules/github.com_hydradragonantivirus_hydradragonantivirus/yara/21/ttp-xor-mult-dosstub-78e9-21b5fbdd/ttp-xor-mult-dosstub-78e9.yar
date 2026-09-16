rule TTP_XOR_MULT_DOSStub_78e9 {
  strings:
    $key_78e9 = { 2c 81 [2] 58 99 [2] 1f 9b [2] 58 8a [2] 16 86 [2] 1a 8c [2] 0d 87 [2] 16 c9 [2] 2b }

  condition:
    any of them
}