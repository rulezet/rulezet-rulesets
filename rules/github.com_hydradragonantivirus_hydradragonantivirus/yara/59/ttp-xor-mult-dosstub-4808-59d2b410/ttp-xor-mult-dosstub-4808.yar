rule TTP_XOR_MULT_DOSStub_4808 {
  strings:
    $key_4808 = { 1c 60 [2] 68 78 [2] 2f 7a [2] 68 6b [2] 26 67 [2] 2a 6d [2] 3d 66 [2] 26 28 [2] 1b }

  condition:
    any of them
}