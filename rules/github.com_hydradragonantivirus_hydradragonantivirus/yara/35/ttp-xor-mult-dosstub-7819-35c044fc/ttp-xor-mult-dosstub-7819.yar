rule TTP_XOR_MULT_DOSStub_7819 {
  strings:
    $key_7819 = { 2c 71 [2] 58 69 [2] 1f 6b [2] 58 7a [2] 16 76 [2] 1a 7c [2] 0d 77 [2] 16 39 [2] 2b }

  condition:
    any of them
}