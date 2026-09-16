rule TTP_XOR_MULT_DOSStub_5366 {
  strings:
    $key_5366 = { 07 0e [2] 73 16 [2] 34 14 [2] 73 05 [2] 3d 09 [2] 31 03 [2] 26 08 [2] 3d 46 [2] 00 }

  condition:
    any of them
}