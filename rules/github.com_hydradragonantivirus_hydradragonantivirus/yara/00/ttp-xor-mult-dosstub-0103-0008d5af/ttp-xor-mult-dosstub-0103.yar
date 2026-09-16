rule TTP_XOR_MULT_DOSStub_0103 {
  strings:
    $key_0103 = { 55 6b [2] 21 73 [2] 66 71 [2] 21 60 [2] 6f 6c [2] 63 66 [2] 74 6d [2] 6f 23 [2] 52 }

  condition:
    any of them
}