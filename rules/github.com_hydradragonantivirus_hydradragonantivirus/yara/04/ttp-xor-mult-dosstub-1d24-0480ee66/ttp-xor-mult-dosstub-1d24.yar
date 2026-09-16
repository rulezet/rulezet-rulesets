rule TTP_XOR_MULT_DOSStub_1d24 {
  strings:
    $key_1d24 = { 49 4c [2] 3d 54 [2] 7a 56 [2] 3d 47 [2] 73 4b [2] 7f 41 [2] 68 4a [2] 73 04 [2] 4e }

  condition:
    any of them
}