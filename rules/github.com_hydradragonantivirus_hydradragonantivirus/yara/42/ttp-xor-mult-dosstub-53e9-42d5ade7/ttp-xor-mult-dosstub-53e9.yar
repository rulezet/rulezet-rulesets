rule TTP_XOR_MULT_DOSStub_53e9 {
  strings:
    $key_53e9 = { 07 81 [2] 73 99 [2] 34 9b [2] 73 8a [2] 3d 86 [2] 31 8c [2] 26 87 [2] 3d c9 [2] 00 }

  condition:
    any of them
}