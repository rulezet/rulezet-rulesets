rule TTP_XOR_MULT_DOSStub_7453 {
  strings:
    $key_7453 = { 20 3b [2] 54 23 [2] 13 21 [2] 54 30 [2] 1a 3c [2] 16 36 [2] 01 3d [2] 1a 73 [2] 27 }

  condition:
    any of them
}