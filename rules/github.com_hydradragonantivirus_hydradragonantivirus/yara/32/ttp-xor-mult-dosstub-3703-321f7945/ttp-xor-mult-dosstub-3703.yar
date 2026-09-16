rule TTP_XOR_MULT_DOSStub_3703 {
  strings:
    $key_3703 = { 63 6b [2] 17 73 [2] 50 71 [2] 17 60 [2] 59 6c [2] 55 66 [2] 42 6d [2] 59 23 [2] 64 }

  condition:
    any of them
}