rule TTP_XOR_MULT_DOSStub_6503 {
  strings:
    $key_6503 = { 31 6b [2] 45 73 [2] 02 71 [2] 45 60 [2] 0b 6c [2] 07 66 [2] 10 6d [2] 0b 23 [2] 36 }

  condition:
    any of them
}