rule TTP_XOR_MULT_DOSStub_4158 {
  strings:
    $key_4158 = { 15 30 [2] 61 28 [2] 26 2a [2] 61 3b [2] 2f 37 [2] 23 3d [2] 34 36 [2] 2f 78 [2] 12 }

  condition:
    any of them
}