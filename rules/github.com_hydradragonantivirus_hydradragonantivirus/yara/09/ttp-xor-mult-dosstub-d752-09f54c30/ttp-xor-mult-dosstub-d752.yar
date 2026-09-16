rule TTP_XOR_MULT_DOSStub_d752 {
  strings:
    $key_d752 = { 83 3a [2] f7 22 [2] b0 20 [2] f7 31 [2] b9 3d [2] b5 37 [2] a2 3c [2] b9 72 [2] 84 }

  condition:
    any of them
}