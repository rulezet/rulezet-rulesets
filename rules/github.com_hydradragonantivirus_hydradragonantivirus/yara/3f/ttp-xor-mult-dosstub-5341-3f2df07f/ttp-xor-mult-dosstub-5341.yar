rule TTP_XOR_MULT_DOSStub_5341 {
  strings:
    $key_5341 = { 07 29 [2] 73 31 [2] 34 33 [2] 73 22 [2] 3d 2e [2] 31 24 [2] 26 2f [2] 3d 61 [2] 00 }

  condition:
    any of them
}