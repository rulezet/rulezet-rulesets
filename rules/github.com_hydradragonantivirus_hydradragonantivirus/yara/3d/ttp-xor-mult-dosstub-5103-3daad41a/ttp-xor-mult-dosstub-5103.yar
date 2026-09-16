rule TTP_XOR_MULT_DOSStub_5103 {
  strings:
    $key_5103 = { 05 6b [2] 71 73 [2] 36 71 [2] 71 60 [2] 3f 6c [2] 33 66 [2] 24 6d [2] 3f 23 [2] 02 }

  condition:
    any of them
}