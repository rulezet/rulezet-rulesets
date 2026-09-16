rule TTP_XOR_MULT_DOSStub_1d16 {
  strings:
    $key_1d16 = { 49 7e [2] 3d 66 [2] 7a 64 [2] 3d 75 [2] 73 79 [2] 7f 73 [2] 68 78 [2] 73 36 [2] 4e }

  condition:
    any of them
}