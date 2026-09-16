rule TTP_XOR_MULT_DOSStub_c755 {
  strings:
    $key_c755 = { 93 3d [2] e7 25 [2] a0 27 [2] e7 36 [2] a9 3a [2] a5 30 [2] b2 3b [2] a9 75 [2] 94 }

  condition:
    any of them
}