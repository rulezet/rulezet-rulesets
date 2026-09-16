rule TTP_XOR_MULT_DOSStub_3158 {
  strings:
    $key_3158 = { 65 30 [2] 11 28 [2] 56 2a [2] 11 3b [2] 5f 37 [2] 53 3d [2] 44 36 [2] 5f 78 [2] 62 }

  condition:
    any of them
}