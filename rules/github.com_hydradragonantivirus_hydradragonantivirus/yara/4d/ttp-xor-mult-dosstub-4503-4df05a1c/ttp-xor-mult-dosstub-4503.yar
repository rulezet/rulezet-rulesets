rule TTP_XOR_MULT_DOSStub_4503 {
  strings:
    $key_4503 = { 11 6b [2] 65 73 [2] 22 71 [2] 65 60 [2] 2b 6c [2] 27 66 [2] 30 6d [2] 2b 23 [2] 16 }

  condition:
    any of them
}