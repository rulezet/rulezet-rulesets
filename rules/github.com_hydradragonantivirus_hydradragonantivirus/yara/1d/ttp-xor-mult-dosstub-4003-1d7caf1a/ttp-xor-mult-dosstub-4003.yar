rule TTP_XOR_MULT_DOSStub_4003 {
  strings:
    $key_4003 = { 14 6b [2] 60 73 [2] 27 71 [2] 60 60 [2] 2e 6c [2] 22 66 [2] 35 6d [2] 2e 23 [2] 13 }

  condition:
    any of them
}