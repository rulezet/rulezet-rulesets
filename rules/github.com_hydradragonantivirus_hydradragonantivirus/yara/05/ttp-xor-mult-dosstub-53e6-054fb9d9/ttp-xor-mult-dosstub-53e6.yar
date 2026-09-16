rule TTP_XOR_MULT_DOSStub_53e6 {
  strings:
    $key_53e6 = { 07 8e [2] 73 96 [2] 34 94 [2] 73 85 [2] 3d 89 [2] 31 83 [2] 26 88 [2] 3d c6 [2] 00 }

  condition:
    any of them
}