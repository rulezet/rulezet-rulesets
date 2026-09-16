rule TTP_XOR_MULT_DOSStub_6353 {
  strings:
    $key_6353 = { 37 3b [2] 43 23 [2] 04 21 [2] 43 30 [2] 0d 3c [2] 01 36 [2] 16 3d [2] 0d 73 [2] 30 }

  condition:
    any of them
}