rule TTP_XOR_MULT_DOSStub_5376 {
  strings:
    $key_5376 = { 07 1e [2] 73 06 [2] 34 04 [2] 73 15 [2] 3d 19 [2] 31 13 [2] 26 18 [2] 3d 56 [2] 00 }

  condition:
    any of them
}