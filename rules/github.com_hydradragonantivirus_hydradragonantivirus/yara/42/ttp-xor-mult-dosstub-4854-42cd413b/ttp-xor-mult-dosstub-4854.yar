rule TTP_XOR_MULT_DOSStub_4854 {
  strings:
    $key_4854 = { 1c 3c [2] 68 24 [2] 2f 26 [2] 68 37 [2] 26 3b [2] 2a 31 [2] 3d 3a [2] 26 74 [2] 1b }

  condition:
    any of them
}