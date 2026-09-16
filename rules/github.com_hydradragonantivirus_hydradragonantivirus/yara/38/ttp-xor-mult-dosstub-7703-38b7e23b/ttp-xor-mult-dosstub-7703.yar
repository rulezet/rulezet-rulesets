rule TTP_XOR_MULT_DOSStub_7703 {
  strings:
    $key_7703 = { 23 6b [2] 57 73 [2] 10 71 [2] 57 60 [2] 19 6c [2] 15 66 [2] 02 6d [2] 19 23 [2] 24 }

  condition:
    any of them
}