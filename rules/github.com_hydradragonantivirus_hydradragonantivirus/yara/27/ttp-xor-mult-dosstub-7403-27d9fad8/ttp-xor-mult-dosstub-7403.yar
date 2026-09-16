rule TTP_XOR_MULT_DOSStub_7403 {
  strings:
    $key_7403 = { 20 6b [2] 54 73 [2] 13 71 [2] 54 60 [2] 1a 6c [2] 16 66 [2] 01 6d [2] 1a 23 [2] 27 }

  condition:
    any of them
}