rule TTP_XOR_MULT_DOSStub_1d15 {
  strings:
    $key_1d15 = { 49 7d [2] 3d 65 [2] 7a 67 [2] 3d 76 [2] 73 7a [2] 7f 70 [2] 68 7b [2] 73 35 [2] 4e }

  condition:
    any of them
}