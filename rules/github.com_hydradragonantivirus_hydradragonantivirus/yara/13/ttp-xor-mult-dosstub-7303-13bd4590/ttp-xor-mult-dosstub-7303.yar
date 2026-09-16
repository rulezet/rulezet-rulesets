rule TTP_XOR_MULT_DOSStub_7303 {
  strings:
    $key_7303 = { 27 6b [2] 53 73 [2] 14 71 [2] 53 60 [2] 1d 6c [2] 11 66 [2] 06 6d [2] 1d 23 [2] 20 }

  condition:
    any of them
}