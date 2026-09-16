rule TTP_XOR_MULT_DOSStub_1503 {
  strings:
    $key_1503 = { 41 6b [2] 35 73 [2] 72 71 [2] 35 60 [2] 7b 6c [2] 77 66 [2] 60 6d [2] 7b 23 [2] 46 }

  condition:
    any of them
}