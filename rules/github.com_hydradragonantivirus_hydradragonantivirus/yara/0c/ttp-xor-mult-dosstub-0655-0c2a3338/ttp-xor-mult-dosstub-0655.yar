rule TTP_XOR_MULT_DOSStub_0655 {
  strings:
    $key_0655 = { 52 3d [2] 26 25 [2] 61 27 [2] 26 36 [2] 68 3a [2] 64 30 [2] 73 3b [2] 68 75 [2] 55 }

  condition:
    any of them
}