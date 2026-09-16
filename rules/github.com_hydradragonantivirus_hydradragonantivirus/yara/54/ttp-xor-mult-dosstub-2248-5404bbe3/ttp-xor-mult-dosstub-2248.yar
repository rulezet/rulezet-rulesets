rule TTP_XOR_MULT_DOSStub_2248 {
  strings:
    $key_2248 = { 76 20 [2] 02 38 [2] 45 3a [2] 02 2b [2] 4c 27 [2] 40 2d [2] 57 26 [2] 4c 68 [2] 71 }

  condition:
    any of them
}