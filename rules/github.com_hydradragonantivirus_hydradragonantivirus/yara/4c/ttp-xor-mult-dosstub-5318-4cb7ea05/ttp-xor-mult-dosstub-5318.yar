rule TTP_XOR_MULT_DOSStub_5318 {
  strings:
    $key_5318 = { 07 70 [2] 73 68 [2] 34 6a [2] 73 7b [2] 3d 77 [2] 31 7d [2] 26 76 [2] 3d 38 [2] 00 }

  condition:
    any of them
}