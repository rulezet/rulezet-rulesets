rule TTP_XOR_MULT_DOSStub_5153 {
  strings:
    $key_5153 = { 05 3b [2] 71 23 [2] 36 21 [2] 71 30 [2] 3f 3c [2] 33 36 [2] 24 3d [2] 3f 73 [2] 02 }

  condition:
    any of them
}