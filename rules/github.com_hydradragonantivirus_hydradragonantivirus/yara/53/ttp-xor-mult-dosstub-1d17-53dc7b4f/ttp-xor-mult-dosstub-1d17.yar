rule TTP_XOR_MULT_DOSStub_1d17 {
  strings:
    $key_1d17 = { 49 7f [2] 3d 67 [2] 7a 65 [2] 3d 74 [2] 73 78 [2] 7f 72 [2] 68 79 [2] 73 37 [2] 4e }

  condition:
    any of them
}