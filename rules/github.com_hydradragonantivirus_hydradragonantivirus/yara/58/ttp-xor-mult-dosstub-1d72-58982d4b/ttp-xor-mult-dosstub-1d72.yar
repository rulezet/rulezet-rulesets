rule TTP_XOR_MULT_DOSStub_1d72 {
  strings:
    $key_1d72 = { 49 1a [2] 3d 02 [2] 7a 00 [2] 3d 11 [2] 73 1d [2] 7f 17 [2] 68 1c [2] 73 52 [2] 4e }

  condition:
    any of them
}