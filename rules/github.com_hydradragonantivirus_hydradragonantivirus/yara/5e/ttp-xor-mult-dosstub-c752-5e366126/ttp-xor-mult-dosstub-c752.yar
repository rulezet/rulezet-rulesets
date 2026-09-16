rule TTP_XOR_MULT_DOSStub_c752 {
  strings:
    $key_c752 = { 93 3a [2] e7 22 [2] a0 20 [2] e7 31 [2] a9 3d [2] a5 37 [2] b2 3c [2] a9 72 [2] 94 }

  condition:
    any of them
}