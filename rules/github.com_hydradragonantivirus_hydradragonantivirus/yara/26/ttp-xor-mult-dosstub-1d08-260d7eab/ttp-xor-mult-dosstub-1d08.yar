rule TTP_XOR_MULT_DOSStub_1d08 {
  strings:
    $key_1d08 = { 49 60 [2] 3d 78 [2] 7a 7a [2] 3d 6b [2] 73 67 [2] 7f 6d [2] 68 66 [2] 73 28 [2] 4e }

  condition:
    any of them
}