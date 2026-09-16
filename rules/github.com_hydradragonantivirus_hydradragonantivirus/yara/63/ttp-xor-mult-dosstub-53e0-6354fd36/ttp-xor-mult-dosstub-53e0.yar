rule TTP_XOR_MULT_DOSStub_53e0 {
  strings:
    $key_53e0 = { 07 88 [2] 73 90 [2] 34 92 [2] 73 83 [2] 3d 8f [2] 31 85 [2] 26 8e [2] 3d c0 [2] 00 }

  condition:
    any of them
}