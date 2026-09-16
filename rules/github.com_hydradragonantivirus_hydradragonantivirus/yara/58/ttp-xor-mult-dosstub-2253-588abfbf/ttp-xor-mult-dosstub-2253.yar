rule TTP_XOR_MULT_DOSStub_2253 {
  strings:
    $key_2253 = { 76 3b [2] 02 23 [2] 45 21 [2] 02 30 [2] 4c 3c [2] 40 36 [2] 57 3d [2] 4c 73 [2] 71 }

  condition:
    any of them
}