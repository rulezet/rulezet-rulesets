rule TTP_XOR_MULT_DOSStub_5367 {
  strings:
    $key_5367 = { 07 0f [2] 73 17 [2] 34 15 [2] 73 04 [2] 3d 08 [2] 31 02 [2] 26 09 [2] 3d 47 [2] 00 }

  condition:
    any of them
}