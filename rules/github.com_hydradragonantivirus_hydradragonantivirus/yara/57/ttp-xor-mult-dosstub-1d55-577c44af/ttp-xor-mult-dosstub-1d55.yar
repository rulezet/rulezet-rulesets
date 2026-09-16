rule TTP_XOR_MULT_DOSStub_1d55 {
  strings:
    $key_1d55 = { 49 3d [2] 3d 25 [2] 7a 27 [2] 3d 36 [2] 73 3a [2] 7f 30 [2] 68 3b [2] 73 75 [2] 4e }

  condition:
    any of them
}