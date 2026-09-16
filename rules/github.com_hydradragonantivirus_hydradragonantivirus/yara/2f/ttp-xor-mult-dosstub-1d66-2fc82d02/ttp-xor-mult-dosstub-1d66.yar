rule TTP_XOR_MULT_DOSStub_1d66 {
  strings:
    $key_1d66 = { 49 0e [2] 3d 16 [2] 7a 14 [2] 3d 05 [2] 73 09 [2] 7f 03 [2] 68 08 [2] 73 46 [2] 4e }

  condition:
    any of them
}