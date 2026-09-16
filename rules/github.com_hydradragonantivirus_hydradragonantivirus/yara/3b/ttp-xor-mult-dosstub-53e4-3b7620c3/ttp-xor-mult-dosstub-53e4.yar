rule TTP_XOR_MULT_DOSStub_53e4 {
  strings:
    $key_53e4 = { 07 8c [2] 73 94 [2] 34 96 [2] 73 87 [2] 3d 8b [2] 31 81 [2] 26 8a [2] 3d c4 [2] 00 }

  condition:
    any of them
}