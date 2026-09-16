rule TTP_XOR_MULT_DOSStub_5312 {
  strings:
    $key_5312 = { 07 7a [2] 73 62 [2] 34 60 [2] 73 71 [2] 3d 7d [2] 31 77 [2] 26 7c [2] 3d 32 [2] 00 }

  condition:
    any of them
}