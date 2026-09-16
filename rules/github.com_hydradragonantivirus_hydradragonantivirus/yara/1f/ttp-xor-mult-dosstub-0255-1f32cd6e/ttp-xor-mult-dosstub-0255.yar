rule TTP_XOR_MULT_DOSStub_0255 {
  strings:
    $key_0255 = { 56 3d [2] 22 25 [2] 65 27 [2] 22 36 [2] 6c 3a [2] 60 30 [2] 77 3b [2] 6c 75 [2] 51 }

  condition:
    any of them
}