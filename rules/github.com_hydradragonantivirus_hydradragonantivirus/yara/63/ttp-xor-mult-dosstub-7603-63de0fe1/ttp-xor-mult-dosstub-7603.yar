rule TTP_XOR_MULT_DOSStub_7603 {
  strings:
    $key_7603 = { 22 6b [2] 56 73 [2] 11 71 [2] 56 60 [2] 18 6c [2] 14 66 [2] 03 6d [2] 18 23 [2] 25 }

  condition:
    any of them
}