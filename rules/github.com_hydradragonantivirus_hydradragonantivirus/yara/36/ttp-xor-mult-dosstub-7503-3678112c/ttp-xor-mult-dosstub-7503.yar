rule TTP_XOR_MULT_DOSStub_7503 {
  strings:
    $key_7503 = { 21 6b [2] 55 73 [2] 12 71 [2] 55 60 [2] 1b 6c [2] 17 66 [2] 00 6d [2] 1b 23 [2] 26 }

  condition:
    any of them
}