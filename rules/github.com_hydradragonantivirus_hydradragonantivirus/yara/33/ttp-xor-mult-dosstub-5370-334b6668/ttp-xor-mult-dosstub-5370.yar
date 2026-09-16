rule TTP_XOR_MULT_DOSStub_5370 {
  strings:
    $key_5370 = { 07 18 [2] 73 00 [2] 34 02 [2] 73 13 [2] 3d 1f [2] 31 15 [2] 26 1e [2] 3d 50 [2] 00 }

  condition:
    any of them
}