rule TTP_XOR_MULT_DOSStub_4863 {
  strings:
    $key_4863 = { 1c 0b [2] 68 13 [2] 2f 11 [2] 68 00 [2] 26 0c [2] 2a 06 [2] 3d 0d [2] 26 43 [2] 1b }

  condition:
    any of them
}