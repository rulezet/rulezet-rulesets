rule TTP_XOR_MULT_DOSStub_78e8 {
  strings:
    $key_78e8 = { 2c 80 [2] 58 98 [2] 1f 9a [2] 58 8b [2] 16 87 [2] 1a 8d [2] 0d 86 [2] 16 c8 [2] 2b }

  condition:
    any of them
}