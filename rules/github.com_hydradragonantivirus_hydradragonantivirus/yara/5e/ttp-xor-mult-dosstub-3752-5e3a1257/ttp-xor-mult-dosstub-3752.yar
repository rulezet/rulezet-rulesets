rule TTP_XOR_MULT_DOSStub_3752 {
  strings:
    $key_3752 = { 63 3a [2] 17 22 [2] 50 20 [2] 17 31 [2] 59 3d [2] 55 37 [2] 42 3c [2] 59 72 [2] 64 }

  condition:
    any of them
}