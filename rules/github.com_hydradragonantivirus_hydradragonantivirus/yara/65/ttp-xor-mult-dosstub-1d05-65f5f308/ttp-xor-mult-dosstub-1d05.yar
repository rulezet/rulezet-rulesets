rule TTP_XOR_MULT_DOSStub_1d05 {
  strings:
    $key_1d05 = { 49 6d [2] 3d 75 [2] 7a 77 [2] 3d 66 [2] 73 6a [2] 7f 60 [2] 68 6b [2] 73 25 [2] 4e }

  condition:
    any of them
}