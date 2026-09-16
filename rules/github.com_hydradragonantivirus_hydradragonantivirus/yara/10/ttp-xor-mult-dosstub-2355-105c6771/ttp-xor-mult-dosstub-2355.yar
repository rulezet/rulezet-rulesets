rule TTP_XOR_MULT_DOSStub_2355 {
  strings:
    $key_2355 = { 77 3d [2] 03 25 [2] 44 27 [2] 03 36 [2] 4d 3a [2] 41 30 [2] 56 3b [2] 4d 75 [2] 70 }

  condition:
    any of them
}