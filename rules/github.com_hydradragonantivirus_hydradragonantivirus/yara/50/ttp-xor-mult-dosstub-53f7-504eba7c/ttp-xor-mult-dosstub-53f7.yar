rule TTP_XOR_MULT_DOSStub_53f7 {
  strings:
    $key_53f7 = { 07 9f [2] 73 87 [2] 34 85 [2] 73 94 [2] 3d 98 [2] 31 92 [2] 26 99 [2] 3d d7 [2] 00 }

  condition:
    any of them
}