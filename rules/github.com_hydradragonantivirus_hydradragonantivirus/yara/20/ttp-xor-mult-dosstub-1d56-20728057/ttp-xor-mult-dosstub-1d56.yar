rule TTP_XOR_MULT_DOSStub_1d56 {
  strings:
    $key_1d56 = { 49 3e [2] 3d 26 [2] 7a 24 [2] 3d 35 [2] 73 39 [2] 7f 33 [2] 68 38 [2] 73 76 [2] 4e }

  condition:
    any of them
}