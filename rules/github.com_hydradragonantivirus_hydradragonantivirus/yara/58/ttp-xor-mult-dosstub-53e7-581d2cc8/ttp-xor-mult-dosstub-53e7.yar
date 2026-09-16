rule TTP_XOR_MULT_DOSStub_53e7 {
  strings:
    $key_53e7 = { 07 8f [2] 73 97 [2] 34 95 [2] 73 84 [2] 3d 88 [2] 31 82 [2] 26 89 [2] 3d c7 [2] 00 }

  condition:
    any of them
}