rule TTP_XOR_MULT_DOSStub_2003 {
  strings:
    $key_2003 = { 74 6b [2] 00 73 [2] 47 71 [2] 00 60 [2] 4e 6c [2] 42 66 [2] 55 6d [2] 4e 23 [2] 73 }

  condition:
    any of them
}