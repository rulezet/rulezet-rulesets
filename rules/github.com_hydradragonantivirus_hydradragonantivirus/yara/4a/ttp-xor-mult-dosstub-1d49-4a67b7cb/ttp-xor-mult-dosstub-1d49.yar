rule TTP_XOR_MULT_DOSStub_1d49 {
  strings:
    $key_1d49 = { 49 21 [2] 3d 39 [2] 7a 3b [2] 3d 2a [2] 73 26 [2] 7f 2c [2] 68 27 [2] 73 69 [2] 4e }

  condition:
    any of them
}