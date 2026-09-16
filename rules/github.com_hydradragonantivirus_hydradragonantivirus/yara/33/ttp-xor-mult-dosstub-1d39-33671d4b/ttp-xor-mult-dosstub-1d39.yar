rule TTP_XOR_MULT_DOSStub_1d39 {
  strings:
    $key_1d39 = { 49 51 [2] 3d 49 [2] 7a 4b [2] 3d 5a [2] 73 56 [2] 7f 5c [2] 68 57 [2] 73 19 [2] 4e }

  condition:
    any of them
}