rule TTP_XOR_MULT_DOSStub_0312 {
  strings:
    $key_0312 = { 57 7a [2] 23 62 [2] 64 60 [2] 23 71 [2] 6d 7d [2] 61 77 [2] 76 7c [2] 6d 32 [2] 50 }

  condition:
    any of them
}