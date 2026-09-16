rule TTP_XOR_MULT_DOSStub_74f5 {
  strings:
    $key_74f5 = { 20 9d [2] 54 85 [2] 13 87 [2] 54 96 [2] 1a 9a [2] 16 90 [2] 01 9b [2] 1a d5 [2] 27 }

  condition:
    any of them
}