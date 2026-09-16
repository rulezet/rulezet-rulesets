rule TTP_XOR_MULT_DOSStub_a752 {
  strings:
    $key_a752 = { f3 3a [2] 87 22 [2] c0 20 [2] 87 31 [2] c9 3d [2] c5 37 [2] d2 3c [2] c9 72 [2] f4 }

  condition:
    any of them
}