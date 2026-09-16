rule TTP_XOR_MULT_DOSStub_1d32 {
  strings:
    $key_1d32 = { 49 5a [2] 3d 42 [2] 7a 40 [2] 3d 51 [2] 73 5d [2] 7f 57 [2] 68 5c [2] 73 12 [2] 4e }

  condition:
    any of them
}