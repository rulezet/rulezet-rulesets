rule TTP_XOR_MULT_DOSStub_0403 {
  strings:
    $key_0403 = { 50 6b [2] 24 73 [2] 63 71 [2] 24 60 [2] 6a 6c [2] 66 66 [2] 71 6d [2] 6a 23 [2] 57 }

  condition:
    any of them
}