rule TTP_XOR_MULT_DOSStub_1d34 {
  strings:
    $key_1d34 = { 49 5c [2] 3d 44 [2] 7a 46 [2] 3d 57 [2] 73 5b [2] 7f 51 [2] 68 5a [2] 73 14 [2] 4e }

  condition:
    any of them
}