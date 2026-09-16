rule TTP_XOR_MULT_DOSStub_0303 {
  strings:
    $key_0303 = { 57 6b [2] 23 73 [2] 64 71 [2] 23 60 [2] 6d 6c [2] 61 66 [2] 76 6d [2] 6d 23 [2] 50 }

  condition:
    any of them
}