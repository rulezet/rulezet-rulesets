rule TTP_XOR_MULT_DOSStub_7868 {
  strings:
    $key_7868 = { 2c 00 [2] 58 18 [2] 1f 1a [2] 58 0b [2] 16 07 [2] 1a 0d [2] 0d 06 [2] 16 48 [2] 2b }

  condition:
    any of them
}