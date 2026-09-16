rule TTP_XOR_MULT_DOSStub_1d68 {
  strings:
    $key_1d68 = { 49 00 [2] 3d 18 [2] 7a 1a [2] 3d 0b [2] 73 07 [2] 7f 0d [2] 68 06 [2] 73 48 [2] 4e }

  condition:
    any of them
}