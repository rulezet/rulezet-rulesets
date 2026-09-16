rule TTP_XOR_MULT_DOSStub_0853 {
  strings:
    $key_0853 = { 5c 3b [2] 28 23 [2] 6f 21 [2] 28 30 [2] 66 3c [2] 6a 36 [2] 7d 3d [2] 66 73 [2] 5b }

  condition:
    any of them
}