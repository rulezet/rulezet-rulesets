rule TTP_XOR_MULT_DOSStub_6752 {
  strings:
    $key_6752 = { 33 3a [2] 47 22 [2] 00 20 [2] 47 31 [2] 09 3d [2] 05 37 [2] 12 3c [2] 09 72 [2] 34 }

  condition:
    any of them
}