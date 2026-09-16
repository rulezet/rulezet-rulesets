rule TTP_XOR_MULT_DOSStub_5378 {
  strings:
    $key_5378 = { 07 10 [2] 73 08 [2] 34 0a [2] 73 1b [2] 3d 17 [2] 31 1d [2] 26 16 [2] 3d 58 [2] 00 }

  condition:
    any of them
}