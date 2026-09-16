rule TTP_XOR_MULT_DOSStub_1d04 {
  strings:
    $key_1d04 = { 49 6c [2] 3d 74 [2] 7a 76 [2] 3d 67 [2] 73 6b [2] 7f 61 [2] 68 6a [2] 73 24 [2] 4e }

  condition:
    any of them
}