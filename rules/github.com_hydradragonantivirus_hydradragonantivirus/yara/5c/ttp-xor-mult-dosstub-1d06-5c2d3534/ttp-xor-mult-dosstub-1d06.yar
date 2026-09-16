rule TTP_XOR_MULT_DOSStub_1d06 {
  strings:
    $key_1d06 = { 49 6e [2] 3d 76 [2] 7a 74 [2] 3d 65 [2] 73 69 [2] 7f 63 [2] 68 68 [2] 73 26 [2] 4e }

  condition:
    any of them
}