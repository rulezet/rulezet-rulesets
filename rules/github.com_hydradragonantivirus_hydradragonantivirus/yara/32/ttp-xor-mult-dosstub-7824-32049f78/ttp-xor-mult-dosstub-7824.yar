rule TTP_XOR_MULT_DOSStub_7824 {
  strings:
    $key_7824 = { 2c 4c [2] 58 54 [2] 1f 56 [2] 58 47 [2] 16 4b [2] 1a 41 [2] 0d 4a [2] 16 04 [2] 2b }

  condition:
    any of them
}