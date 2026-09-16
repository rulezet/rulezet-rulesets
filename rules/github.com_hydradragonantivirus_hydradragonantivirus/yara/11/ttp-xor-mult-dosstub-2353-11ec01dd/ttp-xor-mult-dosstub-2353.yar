rule TTP_XOR_MULT_DOSStub_2353 {
  strings:
    $key_2353 = { 77 3b [2] 03 23 [2] 44 21 [2] 03 30 [2] 4d 3c [2] 41 36 [2] 56 3d [2] 4d 73 [2] 70 }

  condition:
    any of them
}