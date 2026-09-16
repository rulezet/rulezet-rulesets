rule TTP_XOR_MULT_DOSStub_6355 {
  strings:
    $key_6355 = { 37 3d [2] 43 25 [2] 04 27 [2] 43 36 [2] 0d 3a [2] 01 30 [2] 16 3b [2] 0d 75 [2] 30 }

  condition:
    any of them
}