rule TTP_XOR_MULT_DOSStub_3003 {
  strings:
    $key_3003 = { 64 6b [2] 10 73 [2] 57 71 [2] 10 60 [2] 5e 6c [2] 52 66 [2] 45 6d [2] 5e 23 [2] 63 }

  condition:
    any of them
}