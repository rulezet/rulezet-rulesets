rule TTP_XOR_MULT_DOSStub_53f1 {
  strings:
    $key_53f1 = { 07 99 [2] 73 81 [2] 34 83 [2] 73 92 [2] 3d 9e [2] 31 94 [2] 26 9f [2] 3d d1 [2] 00 }

  condition:
    any of them
}