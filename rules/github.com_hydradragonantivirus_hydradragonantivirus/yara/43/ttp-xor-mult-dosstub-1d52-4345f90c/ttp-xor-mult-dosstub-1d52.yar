rule TTP_XOR_MULT_DOSStub_1d52 {
  strings:
    $key_1d52 = { 49 3a [2] 3d 22 [2] 7a 20 [2] 3d 31 [2] 73 3d [2] 7f 37 [2] 68 3c [2] 73 72 [2] 4e }

  condition:
    any of them
}