rule TTP_XOR_MULT_DOSStub_1d14 {
  strings:
    $key_1d14 = { 49 7c [2] 3d 64 [2] 7a 66 [2] 3d 77 [2] 73 7b [2] 7f 71 [2] 68 7a [2] 73 34 [2] 4e }

  condition:
    any of them
}