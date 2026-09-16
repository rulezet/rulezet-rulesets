rule TTP_XOR_MULT_DOSStub_4463 {
  strings:
    $key_4463 = { 10 0b [2] 64 13 [2] 23 11 [2] 64 00 [2] 2a 0c [2] 26 06 [2] 31 0d [2] 2a 43 [2] 17 }

  condition:
    any of them
}