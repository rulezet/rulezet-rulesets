rule TTP_XOR_MULT_DOSStub_7353 {
  strings:
    $key_7353 = { 27 3b [2] 53 23 [2] 14 21 [2] 53 30 [2] 1d 3c [2] 11 36 [2] 06 3d [2] 1d 73 [2] 20 }

  condition:
    any of them
}