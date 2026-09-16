rule TTP_XOR_MULT_DOSStub_1d19 {
  strings:
    $key_1d19 = { 49 71 [2] 3d 69 [2] 7a 6b [2] 3d 7a [2] 73 76 [2] 7f 7c [2] 68 77 [2] 73 39 [2] 4e }

  condition:
    any of them
}