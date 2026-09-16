rule TTP_XOR_MULT_DOSStub_c758 {
  strings:
    $key_c758 = { 93 30 [2] e7 28 [2] a0 2a [2] e7 3b [2] a9 37 [2] a5 3d [2] b2 36 [2] a9 78 [2] 94 }

  condition:
    any of them
}