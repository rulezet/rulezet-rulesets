rule TTP_XOR_MULT_DOSStub_1d64 {
  strings:
    $key_1d64 = { 49 0c [2] 3d 14 [2] 7a 16 [2] 3d 07 [2] 73 0b [2] 7f 01 [2] 68 0a [2] 73 44 [2] 4e }

  condition:
    any of them
}