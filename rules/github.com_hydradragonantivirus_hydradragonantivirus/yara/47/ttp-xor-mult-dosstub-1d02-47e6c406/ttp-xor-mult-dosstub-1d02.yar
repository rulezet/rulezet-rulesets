rule TTP_XOR_MULT_DOSStub_1d02 {
  strings:
    $key_1d02 = { 49 6a [2] 3d 72 [2] 7a 70 [2] 3d 61 [2] 73 6d [2] 7f 67 [2] 68 6c [2] 73 22 [2] 4e }

  condition:
    any of them
}