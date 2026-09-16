rule TTP_XOR_MULT_DOSStub_5003 {
  strings:
    $key_5003 = { 04 6b [2] 70 73 [2] 37 71 [2] 70 60 [2] 3e 6c [2] 32 66 [2] 25 6d [2] 3e 23 [2] 03 }

  condition:
    any of them
}