rule TTP_XOR_MULT_DOSStub_64f5 {
  strings:
    $key_64f5 = { 30 9d [2] 44 85 [2] 03 87 [2] 44 96 [2] 0a 9a [2] 06 90 [2] 11 9b [2] 0a d5 [2] 37 }

  condition:
    any of them
}