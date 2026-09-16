rule TTP_XOR_MULT_DOSStub_53f0 {
  strings:
    $key_53f0 = { 07 98 [2] 73 80 [2] 34 82 [2] 73 93 [2] 3d 9f [2] 31 95 [2] 26 9e [2] 3d d0 [2] 00 }

  condition:
    any of them
}