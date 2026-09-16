rule TTP_XOR_MULT_DOSStub_4874 {
  strings:
    $key_4874 = { 1c 1c [2] 68 04 [2] 2f 06 [2] 68 17 [2] 26 1b [2] 2a 11 [2] 3d 1a [2] 26 54 [2] 1b }

  condition:
    any of them
}