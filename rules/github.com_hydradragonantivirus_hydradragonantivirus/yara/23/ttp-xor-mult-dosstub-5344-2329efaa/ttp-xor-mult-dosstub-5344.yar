rule TTP_XOR_MULT_DOSStub_5344 {
  strings:
    $key_5344 = { 07 2c [2] 73 34 [2] 34 36 [2] 73 27 [2] 3d 2b [2] 31 21 [2] 26 2a [2] 3d 64 [2] 00 }

  condition:
    any of them
}