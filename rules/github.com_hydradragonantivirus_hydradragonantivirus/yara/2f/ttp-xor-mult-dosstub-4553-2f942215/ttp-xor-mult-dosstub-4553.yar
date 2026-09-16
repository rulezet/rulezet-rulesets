rule TTP_XOR_MULT_DOSStub_4553 {
  strings:
    $key_4553 = { 11 3b [2] 65 23 [2] 22 21 [2] 65 30 [2] 2b 3c [2] 27 36 [2] 30 3d [2] 2b 73 [2] 16 }

  condition:
    any of them
}