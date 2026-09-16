rule TTP_XOR_MULT_DOSStub_e752 {
  strings:
    $key_e752 = { b3 3a [2] c7 22 [2] 80 20 [2] c7 31 [2] 89 3d [2] 85 37 [2] 92 3c [2] 89 72 [2] b4 }

  condition:
    any of them
}