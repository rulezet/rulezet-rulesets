rule TTP_XOR_MULT_DOSStub_1d22 {
  strings:
    $key_1d22 = { 49 4a [2] 3d 52 [2] 7a 50 [2] 3d 41 [2] 73 4d [2] 7f 47 [2] 68 4c [2] 73 02 [2] 4e }

  condition:
    any of them
}