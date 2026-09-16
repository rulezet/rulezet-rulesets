rule TTP_XOR_MULT_DOSStub_3853 {
  strings:
    $key_3853 = { 6c 3b [2] 18 23 [2] 5f 21 [2] 18 30 [2] 56 3c [2] 5a 36 [2] 4d 3d [2] 56 73 [2] 6b }

  condition:
    any of them
}