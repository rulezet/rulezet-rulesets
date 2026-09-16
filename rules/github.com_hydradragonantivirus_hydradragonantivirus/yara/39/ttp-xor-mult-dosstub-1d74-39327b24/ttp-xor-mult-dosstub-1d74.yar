rule TTP_XOR_MULT_DOSStub_1d74 {
  strings:
    $key_1d74 = { 49 1c [2] 3d 04 [2] 7a 06 [2] 3d 17 [2] 73 1b [2] 7f 11 [2] 68 1a [2] 73 54 [2] 4e }

  condition:
    any of them
}