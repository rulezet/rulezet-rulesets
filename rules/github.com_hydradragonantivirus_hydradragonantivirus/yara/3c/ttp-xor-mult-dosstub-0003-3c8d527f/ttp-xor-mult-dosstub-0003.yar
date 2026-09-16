rule TTP_XOR_MULT_DOSStub_0003 {
  strings:
    $key_0003 = { 54 6b [2] 20 73 [2] 67 71 [2] 20 60 [2] 6e 6c [2] 62 66 [2] 75 6d [2] 6e 23 [2] 53 }

  condition:
    any of them
}