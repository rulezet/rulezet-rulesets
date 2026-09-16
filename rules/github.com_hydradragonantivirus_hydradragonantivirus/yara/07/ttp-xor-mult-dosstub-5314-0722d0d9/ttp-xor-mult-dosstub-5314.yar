rule TTP_XOR_MULT_DOSStub_5314 {
  strings:
    $key_5314 = { 07 7c [2] 73 64 [2] 34 66 [2] 73 77 [2] 3d 7b [2] 31 71 [2] 26 7a [2] 3d 34 [2] 00 }

  condition:
    any of them
}