rule TTP_XOR_MULT_DOSStub_1d71 {
  strings:
    $key_1d71 = { 49 19 [2] 3d 01 [2] 7a 03 [2] 3d 12 [2] 73 1e [2] 7f 14 [2] 68 1f [2] 73 51 [2] 4e }

  condition:
    any of them
}